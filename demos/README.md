# Demo recordings

Deterministic terminal GIFs via [vhs](https://github.com/charmbracelet/vhs).

```bash
# once: install vhs, install termaxa, cd into a demo project (termaxa init)
vhs demos/1-trench-coat.tape     # compound-command bypass, blocked
createdb shop && psql -d shop -f demos/seed.sql
vhs demos/2-blast-radius.tape    # DROP TABLE: 50k rows, 3 dependents
vhs demos/3-rollback.tape        # force push destroyed + restored
```

The hero GIF for the README is not scripted here: it's a screen recording of
**real Claude Code** attempting a force push and hitting the gate. Nothing a
CLI capture can fake sells the product like the actual agent bouncing off it.
