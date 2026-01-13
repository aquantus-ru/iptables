import re

class IptablesParser:
    def parse(self, content):
        tables = {}
        current_table = None

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('*'):
                current_table = line[1:]
                tables[current_table] = {'chains': {}, 'rules': []}
            elif line.startswith(':'):
                # Chain definition
                # :PREROUTING ACCEPT [0:0]
                parts = line[1:].split(' ', 2)
                chain_name = parts[0]
                policy = parts[1]
                counters = parts[2] if len(parts) > 2 else '[0:0]'
                tables[current_table]['chains'][chain_name] = {
                    'policy': policy,
                    'counters': counters
                }
            elif line.startswith('-A'):
                # Rule
                # -A FORWARD -p tcp ...
                # Split only on the first two spaces to get the chain
                parts = line.split(' ', 2)
                chain = parts[1]
                rule_def = parts[2] if len(parts) > 2 else ""

                # Parse rule options
                parsed_options = self._parse_rule_options(rule_def)

                tables[current_table]['rules'].append({
                    'chain': chain,
                    'rule': rule_def,
                    'options': parsed_options,
                    'full_line': line
                })
            elif line == 'COMMIT':
                current_table = None

        return tables

    def _parse_rule_options(self, rule_def):
        """
        Naive parser for rule options.
        Converts '-p tcp -m tcp --dport 80' into a dict/list structure.
        """
        options = {}
        # This is complex because some flags take arguments and some don't.
        # And some arguments can be quoted or lists.
        # For now, let's just try to extract standard ones.

        # Helper to extract value for a flag
        def extract_value(flag):
            match = re.search(fr'{flag}\s+([^\s]+)', rule_def)
            return match.group(1) if match else None

        options['protocol'] = extract_value('-p')
        options['source'] = extract_value('-s')
        options['destination'] = extract_value('-d')
        options['in_interface'] = extract_value('-i')
        options['out_interface'] = extract_value('-o')
        options['jump'] = extract_value('-j')

        # dport/sport often require -m tcp/udp but can appear as --dport
        options['dport'] = extract_value('--dport')
        options['sport'] = extract_value('--sport')

        # State
        if '--state' in rule_def:
             options['state'] = extract_value('--state')
        elif '-m state --state' in rule_def: # Explicit check if regex failed for partial match
             pass

        return options

    def generate(self, tables):
        output = []
        for table_name, table_data in tables.items():
            output.append(f"*{table_name}")
            # sort chains usually? iptables-save outputs them in a specific order usually (built-in first)
            # but preserving order from parse is good if possible. dicts are ordered in python 3.7+
            for chain_name, chain_data in table_data['chains'].items():
                output.append(f":{chain_name} {chain_data['policy']} {chain_data['counters']}")

            for rule in table_data['rules']:
                output.append(f"-A {rule['chain']} {rule['rule']}")

            output.append("COMMIT")
        return "\n".join(output)
