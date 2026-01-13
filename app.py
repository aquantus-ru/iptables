from flask import Flask, render_template, request, redirect, url_for
from iptables_parser import IptablesParser
import os
import json

app = Flask(__name__)
parser = IptablesParser()

DATA_FILE = 'example_iptables.txt'
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        f.write("")

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return parser.parse(f.read())
    return {}

# Store in memory for this session
iptables_data = load_data()

@app.route('/')
def index():
    return render_template('index.html', tables=iptables_data)

@app.route('/add_rule', methods=['GET', 'POST'])
def add_rule():
    if request.method == 'POST':
        table = request.form.get('table')
        chain = request.form.get('chain')

        # Build the rule string
        parts = []

        # Helper to add flag if value exists
        def add_flag(flag, field_name):
            val = request.form.get(field_name)
            if val:
                parts.append(f"{flag} {val}")

        # Protocol
        add_flag('-p', 'protocol')
        if request.form.get('protocol') in ['tcp', 'udp']:
             # implicit -m tcp/udp if protocol is specified?
             # iptables usually does this.
             parts.append(f"-m {request.form.get('protocol')}")

        add_flag('-s', 'source')
        add_flag('-d', 'destination')
        add_flag('-i', 'in_interface')
        add_flag('-o', 'out_interface')
        add_flag('--sport', 'sport')
        add_flag('--dport', 'dport')
        add_flag('-j', 'jump')

        extra = request.form.get('extra_options')
        if extra:
            parts.append(extra)

        rule_def = " ".join(parts)
        full_line = f"-A {chain} {rule_def}"

        # Parse options for display
        parsed_options = parser._parse_rule_options(rule_def)

        if table in iptables_data:
            iptables_data[table]['rules'].append({
                'chain': chain,
                'rule': rule_def,
                'options': parsed_options,
                'full_line': full_line
            })

        return redirect(url_for('index'))

    # Prepare data for dropdowns
    table_chains = {}
    for t_name, t_data in iptables_data.items():
        table_chains[t_name] = list(t_data['chains'].keys())

    return render_template('add_rule.html', tables=iptables_data.keys(), table_chains_json=json.dumps(table_chains))

@app.route('/generate')
def generate():
    generated_config = parser.generate(iptables_data)
    return render_template('generate.html', config=generated_config)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
