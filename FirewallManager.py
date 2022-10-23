from netmiko import netmiko
fw_01 = {'host': '192.168.0.21',
         'username': 'admin',
          'password': 'arpanfirewall',
          'device_type': 'fortinet'
          }
print(f"{'#'*20} Connecting to the Device {'#'*20}")
net_connect  = Netmiko(**fw_01)
# print(net_comect.find_proapt(1)
command = 'show full-configuration'
full_config = net_connect.send_command(command)
print(full_config)
print(f"{'#'*20} Connected {'#'*20}")
