from subprocess import check_output, CalledProcessError
import sys
import re

class Bash:

    def __init__(self, command: str):
        self.command = command

    def execute(self):
        try:
            self.output = str(check_output(self.command, shell=True))

        except CalledProcessError:
            context = 'Command error. Check console output.'
            sys.exit()

    def get_output(self):
        return self.output


def cidr_to_mask(cidr: int) -> str:

    template = '00000000.00000000.00000000.00000000'
    bin_mask = template.replace('0', '1', cidr)

    mask = ''
    for section in bin_mask.split('.'):
        mask += str(eval('0b' + section)) + '.'

    return mask[:-1]


def get_devices() -> dict:

    terminal = Bash('ip a')
    terminal.execute()
    output = terminal.get_output()

    patterns = re.findall("([0-9]+:\s\w+:\s<)", output)

    devices = []

    i = 0
    while i < len(patterns):

        try:
            device_info = re.search("("+patterns[i]+".+)"+patterns[i+1], output).group(1)
        except IndexError:
            device_info = re.search("("+patterns[len(patterns)-1]+".+)$", output).group(1)

        p = re.search("^([0-9]+):\s(\w+):\s[<].+?state\s(\w+)\s", device_info)

        devices.append({})
        devices[i]['id'] = p.group(1)
        devices[i]['name'] = p.group(2)
        devices[i]['state'] = p.group(3)
        devices[i]['ip'] = ' '
        devices[i]['mask'] = ' '

        if 'inet ' in device_info:

            ip = re.search("inet\s(\S+[\/]\d+)\s", device_info)

            devices[i]['ip'] = ip.group(1)
            devices[i]['mask'] = cidr_to_mask(int(re.search("[0-9]+$", devices[i]['ip']).group(0)))

        i += 1

    return devices


def change_ip(device_id: int, add: bool, ip: str = '') -> str:

    device = get_devices()[device_id-1]

    if add:
        action = 'add'
    else:
        action = 'del'
        ip = device['ip']

    if ip == '':
        return 'this device dont have ip'

    command = 'sudo ip addr ' + action + ' ' + ip + ' dev ' + device['name']

    terminal = Bash(command)
    terminal.execute()

    terminal = Bash(' ')
    terminal.execute()

    return terminal.get_output()
