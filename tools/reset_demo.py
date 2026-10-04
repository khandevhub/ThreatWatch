"""Remove ONLY synthetic Simulation Lab data from the ThreatWatch database.

Deletes events sourced by the SOC simulator plus the alerts, AI results,
investigation transitions, and SOAR executions attributed to simulation runs.
Never touches configuration, rules, the knowledge base, or any data that did
not come from the simulation lab. Refuses to run against a database that has
no simulation data.

Usage:
    python tools/reset_demo.py            # report + delete (default DB)
    python tools/reset_demo.py --dry-run  # report only
    DB_FILE=path python tools/reset_demo.py
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import connect, init_db  # noqa: E402


def _counts(db_file):
    with connect(db_file) as connection:
        runs = connection.execute('SELECT COUNT(*) FROM simulation_runs').fetchone()[0]
        sim_events = connection.execute(
            'SELECT COUNT(*) FROM simulation_events').fetchone()[0]
        linked_alerts = connection.execute(
            'SELECT COUNT(DISTINCT alert_id) FROM simulation_run_alerts '
            'WHERE alert_id IS NOT NULL').fetchone()[0]
    return runs, sim_events, linked_alerts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--dry-run', action='store_true',
                        help='Report what would be removed without deleting.')
    args = parser.parse_args(argv)

    db_file = os.environ.get('DB_FILE', 'db.sqlite')
    init_db(db_file)
    runs, sim_events, linked_alerts = _counts(db_file)
    print(f'database: {db_file}')
    print(f'simulation runs: {runs}')
    print(f'simulation events: {sim_events}')
    print(f'alerts attributed to simulation runs: {linked_alerts}')
    if runs == 0 and sim_events == 0 and linked_alerts == 0:
        print('nothing to reset — no simulation data present.')
        return 0
    if args.dry_run:
        print('dry run: no data was deleted.')
        return 0

    import soc_simulation

    result = soc_simulation.delete_simulation_data(db_file=db_file)
    remaining_runs, remaining_events, remaining_alerts = _counts(db_file)
    print('reset complete:', result['simulation_data_removed'])
    print(f'remaining simulation rows: runs={remaining_runs} '
          f'events={remaining_events} alerts={remaining_alerts}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
