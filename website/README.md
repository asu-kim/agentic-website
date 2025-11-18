# Proposed Website

## 1. Environment set up

1) Inside the project's `$ROOT` directory, set up a virtual environment.

    macOS or Linux
    ```
    python3 -m venv .venv
    source .venv/bin/activate
    ```
    
    Window environment 
    ```
    py -m venv .venv
    venv\Scripts\activate.bat
    ```

2) Install Python Dependencies
```
pip install -r requirements.txt
```

3) Check `iotauth` submodule
```
cd $ROOT/iotauth
git submodule update --init --recursive
git checkout agentic-ai
git pull
```

## 2. Run website

You need **five** separate terminal windows to run the experiment.

### Open terminal 1
```
# generate entities
cd $ROOT/iotauth/examples
./initConfigs.sh
./cleanAll.sh
./generateAll.sh -g configs/agentAccess.graph 
```

```
# start Auth
cd $ROOT/iotauth/auth/auth-server
make
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

### Open terminal 2
```
# generate key for delegate access to agent
cd $ROOT/iotauth/entity/node/example_entities
node user.js configs/net1/user.config 
```
Inside the program, enter the following command to delegate access.

The `<trust_level>` argument accepts one of the following values: `high`, `medium`, or `low`.
```
delegateAccess <trust_level>
```
Terminate the program after checking the `sessionKeyID`.

### Open terminal 3
```
cd $ROOT/website
python3 app.py  # py app.py for window
```

### Open terminal 4
```
# install dependencies
cd $ROOT/website
npm install
npm start
```
On the website,
1. Register with username `user` and your password.
2. `Open Agent Access Control` and set the scope for each agent (high, medium, low).
3. Log out or close the window.

If you get `SecurityError: Cannot initialize local storage without a --localstorage-file path` error, use below command to run website
```
NODE_OPTIONS="--localstorage-file=/tmp/node-localstorage.json" npm start
```

### Open terminal 5
```
# run agent
cd $ROOT/agent
python lowTrustAgent.py --keyId 00000000 --items all # email/phone/address/card/all
```
You can save the log using `log.sh`
```
export LOG_DIR="directory path to save logs"
./log.sh lowTrustAgent.py --keyId 00000000 --items all # email/phone/address/card/all
```
