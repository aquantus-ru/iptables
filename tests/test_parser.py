import pytest
from iptables_parser import IptablesParser

@pytest.fixture
def parser():
    return IptablesParser()

def test_parse_simple_table(parser):
    content = """
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
    result = parser.parse(content)
    assert 'filter' in result
    assert 'INPUT' in result['filter']['chains']
    assert len(result['filter']['rules']) == 1
    assert result['filter']['rules'][0]['chain'] == 'INPUT'
    assert result['filter']['rules'][0]['options']['protocol'] == 'tcp'
    assert result['filter']['rules'][0]['options']['dport'] == '22'

def test_generate_simple_table(parser):
    tables = {
        'filter': {
            'chains': {'INPUT': {'policy': 'ACCEPT', 'counters': '[0:0]'}},
            'rules': [
                {'chain': 'INPUT', 'rule': '-p tcp --dport 22 -j ACCEPT'}
            ]
        }
    }
    output = parser.generate(tables)
    assert '*filter' in output
    assert ':INPUT ACCEPT [0:0]' in output
    assert '-A INPUT -p tcp --dport 22 -j ACCEPT' in output
    assert 'COMMIT' in output

def test_parse_complex_rule(parser):
    content = """
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -p tcp -m tcp --dport 16676 -j DNAT --to-destination 10.66.66.67:8899
COMMIT
"""
    result = parser.parse(content)
    rule = result['nat']['rules'][0]
    opts = rule['options']
    assert opts['in_interface'] == 'eth0'
    assert opts['protocol'] == 'tcp'
    assert opts['dport'] == '16676'
    assert opts['jump'] == 'DNAT'

def test_ipv6_rule(parser):
    content = """
*filter
:FORWARD ACCEPT [0:0]
-A FORWARD -d 2001:db8::1/128 -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
"""
    result = parser.parse(content)
    rule = result['filter']['rules'][0]
    opts = rule['options']
    assert opts['destination'] == '2001:db8::1/128'
    assert opts['protocol'] == 'tcp'
