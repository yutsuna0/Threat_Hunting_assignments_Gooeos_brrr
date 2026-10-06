# commands
### Splunk setup

```text-plain
sudo docker run -d --name splunk -p 8000:8000 -p 8089:8089 -e SPLUNK_START_ARGS="--accept-license" -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" -e SPLUNK_PASSWORD='<CREATE_HARD_PASS_PLZZZ>' splunk/splunk:latest
```

Confirming container status:

```text-plain
sudo docker ps -a
```

```text-plain
##This is just example

CONTAINER ID   IMAGE                          COMMAND                  CREATED          STATUS                        PORTS                                                                                                                                        NAMES
dab1ce5de075   splunk/splunk:latest           "/sbin/entrypoint.sh…"   20 minutes ago   Up 20 minutes (healthy)       8065/tcp, 0.0.0.0:8000->8000/tcp, [::]:8000->8000/tcp, 8088/tcp, 8191/tcp, 9887/tcp, 0.0.0.0:8089->8089/tcp, [::]:8089->8089/tcp, 9997/tcp   splunk
```

The following command can be ran to check its logs:

```text-plain
sudo docker logs splunk
```

### Data Sets

Run these commands

```text-plain
git clone https://github.com/splunk/attack_data
python3 -m venv venv
source venv/bin/activate
pip install -r attack_data/bin/requirements.txt
```

Fetching selected attack data sets, make sure to be in a Git repository:

```text-plain
## Sorry I can't download every data set, otherwise my VM would blow up
## It is already really loud from splunk alone
git lfs pull --include=datasets/attack_techniques/T1484.001/
git lfs pull --include=datasets/attack_techniques/T1003.006/
```

The narrower, single-subfolder pulls (`.../T1484.001/snapattack/` and `.../T1003.006/impacket/`) were tried first but returned insufficient data for a reliable hunt – pulling each technique's full folder instead gives access to every available dataset variant for that technique (e.g. `gpo_modification`, `group_policy_created`, `group_policy_deleted` for T1484.001; `impacket` and `mimikatz` for T1003.006), so the best-fitting dataset can be chosen after inspecting what's actually available

```text-plain
tree -h datasets/attack_techniques/T1484.001/                                                                                                                                            
[4.0K]  datasets/attack_techniques/T1484.001/                                                                                                                                                
├── [4.0K]  default_domain_policy_modified                                                                                                                                                   
│   ├── [ 481]  default_domain_policy_modified.yml                                                                                                                                           
│   ├── [ 32K]  security-4688.log                                                                                                                                                            
│   └── [212K]  windows-security.log                                                                                                                                                         
├── [4.0K]  gpo_modification                                                                                                                                                                 
│   ├── [ 422]  gpo_modification.yml                                                                                                                                                         
│   └── [386K]  windows-security.log                                                                                                                                                         
├── [4.0K]  group_policy_created                                                                                                                                                             
│   ├── [ 438]  group_policy_created.yml                                                                                                                                                     
│   ├── [ 916]  windows-admon.log                                                                                                                                                            
│   └── [386K]  windows-security.log                                                                                                                                                         
├── [4.0K]  group_policy_deleted                                                                                                                                                             
│   ├── [ 453]  group_policy_deleted.yml                                                                                                                                                     
│   ├── [1.1K]  windows-admon.log                                                                                                                                                            
│   └── [3.7K]  windows-security.log
├── [4.0K]  group_policy_disabled
│   ├── [ 456]  group_policy_disabled.yml
│   ├── [1.1K]  windows-admon.log
│   └── [2.8K]  windows-security.log
├── [4.0K]  group_policy_new_cse
│   ├── [ 503]  group_policy_new_cse.yml
│   ├── [2.5K]  windows-admon.log
│   └── [9.8K]  windows-security.log
└── [4.0K]  snapattack
    ├── [ 12K]  snapattack.log
    └── [ 441]  snapattack.yml

8 directories, 19 files
```

```text-plain
tree -h datasets/attack_techniques/T1003.006/
[4.0K]  datasets/attack_techniques/T1003.006/
├── [4.0K]  impacket
│   ├── [ 481]  impacket.yml
│   ├── [1.8K]  windows-directory_service.log
│   ├── [4.8K]  windows-security.log
│   ├── [ 10K]  windows-security-xml.log
│   └── [ 495]  zeek-dce_rpc.log
├── [4.0K]  mimikatz
│   ├── [ 398]  mimikatz.yml
│   ├── [ 913]  windows-directory_service.log
│   ├── [4.8K]  windows-security.log
│   ├── [ 16K]  xml-windows-security.log
│   └── [ 248]  zeek-dce_rpc.log
└── [4.0K]  snapattack
    ├── [2.9K]  snapattack.log
    └── [ 420]  snapattack.yml

4 directories, 12 files
```