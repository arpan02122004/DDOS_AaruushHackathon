from netmiko import ConnectHandler
fw_01 = {'host': '10.5.242.60',
         'username': 'admin',
          'password': 'arpanfirewall',
          'device_type': 'fortinet'
          }
print(f"{'#'*20} Connecting to the Device {'#'*20}")
net_connect  = ConnectHandler(**fw_01)
# print(net_comect.find_proapt(1)
command = 'show full-configuration'
full_config = net_connect.send_command(command)
print(full_config)
print(f"{'#'*20} Connected {'#'*20}")
