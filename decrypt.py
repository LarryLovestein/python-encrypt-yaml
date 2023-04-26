import os
import yaml
import sys
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

# Init Vault
with open(os.environ.get('ANSIBLE_VAULT_PASSWORD_FILE')) as password_file:
    vault_pass = password_file.read().strip().encode('utf8')
vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(vault_pass))])

class VaultString:
  def __init__(self, string):
    self.string = string
  def __repr__(self):
    return self.string.decode('utf-8')
  def decrypt(self):
    return vault.decrypt(self.string)
  def update(self, new_value):
    self.string = vault.encrypt(new_value,vault_id="dev").decode('utf-8')
    return self.string

def vault_string_constructor(loader, node):
    return VaultString(loader.construct_scalar(node))

def vault_string_representer(dumper, data):
    return dumper.represent_scalar(u'!vault', str(data), style='|')

yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str

def repr_str(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar(u'!vault', str(data), style='|')
    return dumper.org_represent_str(data)

yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)

yaml.SafeLoader.add_constructor(u'!vault', vault_string_constructor)
yaml.Dumper.add_representer(VaultString, vault_string_representer)

def decrypt_string(obj):
    if type(obj) is dict:
        for k in obj.keys():
            obj[k] = decrypt_string(obj[k])
        return obj
    elif type(obj) is list:
        for k in obj:
            k = decrypt_string(k)
        return obj
    elif type(obj) is VaultString:
        obj = obj.decrypt().decode('utf-8')
        return obj
    else:
        #print(type(obj))
        return obj

def encrypt_string(obj):
    if type(obj) is dict:
        for k in obj.keys():
            obj[k] = encrypt_string(obj[k])
        return obj
    elif type(obj) is list:
        for k in obj:
            k = encrypt_string(k)
        return obj
    elif type(obj) is VaultString:
        obj = obj.update(decrypt_string(obj))
        return obj
    else:
        #print(type(obj))
        return obj

def encrypt_value(new_value):
  return vault.encrypt(new_value,vault_id="dev").decode('utf-8')

keys_to_encrypt= ["apiKey","clientKey","password","recurringPassword","shaDirectPassPhrase","shaHopInPassPhrase","shaHopOutPassPhrase","signature"]

def encrypt_decrypted_values(obj):
  if type(obj) is dict:
      for k in obj.keys():
        if k in keys_to_encrypt:
          obj[k] = encrypt_decrypted_values(encrypt_value(obj[k]))
        else:
          obj[k]=encrypt_decrypted_values(obj[k])
      return obj
  elif type(obj) is list:
      for k in obj:
          k = encrypt_decrypted_values(k)
      return obj
  else:
      #print(type(obj))
      return obj


# Read file
# with open(sys.argv[1], 'r') as file:
#      file_content = yaml.safe_load(file)
#      #print(file_content)
#      for k,v in file_content.items():
#        #print(decrypt_string(v))
#        file_content[k] = decrypt_string(v)

#test
with open(sys.argv[1], 'r') as file:
  file_content = yaml.safe_load(file)
  #print(file_content)
  for k,v in file_content.items():
    file_content[k] = encrypt_decrypted_values(v)

# print(yaml.safe_dump(file_content, sort_keys=False))

with open("decoded_" + sys.argv[1], 'w') as decoded_file:
  decoded_file.write(yaml.safe_dump(file_content,sort_keys=False))


