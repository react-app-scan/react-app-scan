cd ./src/esprima/ && npm i && cd -;
npm install \
    @babel/core \
    @babel/cli \
    @babel/preset-env \
    @babel/plugin-syntax-jsx \
    @babel/preset-typescript \
    @babel/plugin-proposal-class-properties \
    mocha;
python3 -m pip install -r ./requirements.txt;

