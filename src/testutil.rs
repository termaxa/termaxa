//! Test-only isolation for the process-global state this suite reaches into.
//!
//! `TERMAXA_HOME` and the working directory belong to the PROCESS, and cargo
//! runs tests as threads inside one process. Three tests in `paths.rs` used to
//! set them by hand and delete the trees they pointed at, which produced a
//! flake that read as a missing policy (#17) and, on every green run in
//! between, quietly wrote state into the developer's real `~/.termaxa`.
//!
//! Both halves of that came from the same thing: setting up a test correctly
//! took knowledge the test itself did not carry. So the safe path is the only
//! path here. `TestEnv::new` takes the lock, points `TERMAXA_HOME` at a tree
//! this test alone owns, and on drop puts the cwd and the variable back,
//! removes the tree, and fails the test if state landed anywhere else.
//!
//! ```ignore
//! let env = TestEnv::new("my-case");
//! let proj = env.project("proj");        // <root>/proj/.termaxa/policy.yaml
//! let paths = crate::paths::resolve_from(&proj)?;
//! ```
//!
//! One guard per test. `std::sync::Mutex` is not reentrant, so a second
//! `TestEnv::new` while one is alive deadlocks rather than failing.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static GLOBAL_ENV: Mutex<()> = Mutex::new(());
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Take the lock, tolerating poisoning: if a test panicked while holding it,
/// the rest should report their own verdicts instead of failing as collateral
/// and hiding which one actually broke.
fn lock() -> MutexGuard<'static, ()> {
    GLOBAL_ENV.lock().unwrap_or_else(|e| e.into_inner())
}

/// The real `~/.termaxa/projects`, ignoring any `TERMAXA_HOME` override.
///
/// Deliberately not `paths::home_base()`: this has to name the directory the
/// override is protecting, which is exactly the one `home_base` stops
/// returning the moment the guard does its job.
fn real_state_root() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    Some(PathBuf::from(home).join(".termaxa").join("projects"))
}

fn listing(dir: &Path) -> BTreeSet<OsString> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries.flatten().map(|e| e.file_name()).collect(),
        // Absent reads as empty on purpose: a directory that does not exist
        // yet and one that is empty are the same starting point, and the
        // comparison at drop is what has to notice the difference.
        Err(_) => BTreeSet::new(),
    }
}

/// Names present at drop that were not present at construction.
fn arrivals(before: &BTreeSet<OsString>, after: &BTreeSet<OsString>) -> Vec<OsString> {
    after.difference(before).cloned().collect()
}

pub struct TestEnv {
    /// `None` only for the tests in this module that already hold the lock in
    /// order to observe the guard without racing it.
    _lock: Option<MutexGuard<'static, ()>>,
    root: PathBuf,
    previous_home: Option<OsString>,
    previous_cwd: Option<PathBuf>,
    watch: Option<(PathBuf, BTreeSet<OsString>)>,
}

impl TestEnv {
    /// Serialise against every other `TestEnv`, then claim a fresh tree.
    ///
    /// `label` only has to be readable in `/tmp` while a test is running; the
    /// pid and a counter make the path unique, so two tests sharing a label
    /// still get separate trees.
    pub fn new(label: &str) -> Self {
        Self::build(Some(lock()), label)
    }

    fn build(guard: Option<MutexGuard<'static, ()>>, label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "tmx-{}-{}-{}",
            label,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test root must be creatable");

        let previous_home = std::env::var_os("TERMAXA_HOME");
        std::env::set_var("TERMAXA_HOME", root.join("home"));

        let watch = real_state_root().map(|dir| {
            let before = listing(&dir);
            (dir, before)
        });

        Self {
            _lock: guard,
            root,
            previous_home,
            previous_cwd: None,
            watch,
        }
    }

    /// The tree this test owns. Everything it writes belongs under here.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where `TERMAXA_HOME` points for the life of this guard.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// A project directory with a minimal policy, ready for `resolve_from`.
    pub fn project(&self, name: &str) -> PathBuf {
        let proj = self.root.join(name);
        std::fs::create_dir_all(proj.join(".termaxa")).expect("project dir must be creatable");
        std::fs::write(
            proj.join(".termaxa").join("policy.yaml"),
            "version: 1\ndefault: ask\nrules: []\n",
        )
        .expect("policy must be writable");
        proj
    }

    /// Move the process into `dir`, remembering where it came from.
    ///
    /// The original is captured once, so a test may step through several
    /// directories and still land back where it started.
    pub fn chdir(&mut self, dir: &Path) {
        if self.previous_cwd.is_none() {
            self.previous_cwd = std::env::current_dir().ok();
        }
        std::env::set_current_dir(dir).expect("cwd must be settable");
    }

    /// Watch a stand-in directory instead of the real one, so the check at
    /// drop can be tested without writing to anybody's home.
    #[cfg(test)]
    fn watch_instead(&mut self, dir: PathBuf) {
        let before = listing(&dir);
        self.watch = Some((dir, before));
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Step out before deleting: leaving the process in a directory that no
        // longer exists breaks `getcwd` for everything scheduled after it.
        if let Some(cwd) = self.previous_cwd.take() {
            let _ = std::env::set_current_dir(cwd);
        }
        match self.previous_home.take() {
            Some(previous) => std::env::set_var("TERMAXA_HOME", previous),
            // Restoring absence matters as much as restoring a value: a
            // variable left pointing at a deleted tree is the original bug.
            None => std::env::remove_var("TERMAXA_HOME"),
        }

        let strays = self.watch.take().map(|(dir, before)| {
            let found = arrivals(&before, &listing(&dir));
            (dir, found)
        });
        let _ = std::fs::remove_dir_all(&self.root);

        // Never assert into an unwind: a panicking Drop during a panic aborts
        // the process, and the test's own failure is the one worth reading.
        if std::thread::panicking() {
            return;
        }
        if let Some((dir, found)) = strays {
            assert!(
                found.is_empty(),
                "state landed outside this test's tree, in {}: {:?}\n\
                 The suite must not write where the product writes. If this is \
                 a new code path, route it through TERMAXA_HOME rather than \
                 widening this check.",
                dir.display(),
                found
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anti-rot test. If `TestEnv` ever stops exporting `TERMAXA_HOME`,
    /// every test that trusts it keeps passing while writing to the real home
    /// again, which is precisely how the pollution went unnoticed for months.
    /// This is the one assertion that fails when the helper becomes a no-op.
    #[test]
    fn the_guard_actually_redirects_state() {
        let env = TestEnv::new("isolates");
        let paths = crate::paths::resolve_from(&env.project("proj")).expect("must resolve");
        assert!(
            paths.state_dir.starts_with(env.home()),
            "state must land under the guard's home, got {}",
            paths.state_dir.display()
        );
        assert!(paths.state_dir.join("logs").is_dir());
    }

    #[test]
    fn the_guard_puts_everything_back() {
        // Hold the lock across the whole test, so nothing else can move the
        // cwd or the variable between the guard dropping and the assertions.
        // The inner guard is built without taking it again, since a std Mutex
        // is not reentrant.
        let _outer = lock();
        let home_before = std::env::var_os("TERMAXA_HOME");
        let cwd_before = std::env::current_dir().expect("a cwd to return to");

        let root = {
            let mut env = TestEnv::build(None, "restores");
            let proj = env.project("proj");
            env.chdir(&proj);
            assert_ne!(
                std::env::current_dir().ok(),
                Some(cwd_before.clone()),
                "chdir must actually move the process"
            );
            assert_eq!(
                std::env::var_os("TERMAXA_HOME"),
                Some(env.home().into_os_string()),
                "the guard must export its own home while it is alive"
            );
            env.root().to_path_buf()
        };

        assert!(!root.exists(), "the guard must remove its own tree");
        assert_eq!(std::env::var_os("TERMAXA_HOME"), home_before);
        assert_eq!(std::env::current_dir().ok(), Some(cwd_before));
    }

    #[test]
    fn the_guard_fails_loudly_when_state_lands_outside_its_tree() {
        let _outer = lock();
        let decoy = std::env::temp_dir().join(format!("tmx-decoy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&decoy);
        std::fs::create_dir_all(&decoy).expect("decoy must be creatable");

        // The guard reports by panicking, so the expected failure would print
        // a backtrace-looking wall of text on a passing run. Silence just this
        // one, and put the real hook back.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind({
            let decoy = decoy.clone();
            move || {
                let mut env = TestEnv::build(None, "stray");
                env.watch_instead(decoy.clone());
                // Stand in for a test resolving into the real ~/.termaxa.
                std::fs::create_dir_all(decoy.join("proj-deadbeef")).unwrap();
                drop(env);
            }
        });
        std::panic::set_hook(hook);

        let _ = std::fs::remove_dir_all(&decoy);
        assert!(
            outcome.is_err(),
            "a test that writes outside its own tree must fail, not pass quietly"
        );
    }

    #[test]
    fn the_check_only_reports_what_arrived() {
        let names =
            |xs: &[&str]| -> BTreeSet<OsString> { xs.iter().map(|s| OsString::from(*s)).collect() };
        // Pre-existing entries are somebody else's, and a test that removes
        // one is doing something worse than the check is looking for, but it
        // is not what this check is for.
        assert!(arrivals(&names(&["a", "b"]), &names(&["a", "b"])).is_empty());
        assert!(arrivals(&names(&["a", "b"]), &names(&["a"])).is_empty());
        assert_eq!(
            arrivals(&names(&["a"]), &names(&["a", "proj-deadbeef"])),
            vec![OsString::from("proj-deadbeef")]
        );
    }

    #[test]
    fn each_guard_gets_a_tree_of_its_own() {
        let first = TestEnv::new("unique");
        let first_root = first.root().to_path_buf();
        drop(first);
        let second = TestEnv::new("unique");
        assert_ne!(
            first_root,
            second.root(),
            "two guards sharing a label must not share a tree"
        );
    }
}
