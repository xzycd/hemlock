"""Reference data for the naming rules.

The popular-package lists are the typosquat targets. They do not need to be
exhaustive, because attackers imitate things people actually type, and the long
tail of a registry is not worth impersonating. A few hundred names covers
the realistic attack surface and keeps the check instant.
"""

POPULAR_NPM = """
lodash react react-dom react-native chalk debug express axios commander request
moment uuid async tslib semver glob minimist yargs colors ansi-styles
supports-color strip-ansi cross-spawn rimraf fs-extra mkdirp dotenv typescript
webpack eslint prettier jest mocha chai sinon nodemon socket.io mongoose
sequelize redis pg mysql mysql2 body-parser cors helmet morgan jsonwebtoken
bcrypt bcryptjs passport multer nanoid classnames prop-types redux react-redux
styled-components next vue rxjs core-js regenerator-runtime node-fetch
form-data qs cookie cookie-parser ms bytes mime mime-types ejs pug handlebars
marked cheerio jsdom puppeteer playwright sharp ws sass postcss autoprefixer
tailwindcss vite rollup esbuild parcel gulp grunt browserify babel-loader
css-loader style-loader terser uglify-js inquirer ora boxen figlet cli-table3
progress chokidar graceful-fs readable-stream through2 split2 pump
concat-stream buffer safe-buffer string_decoder inherits util-deprecate
object-assign extend deepmerge clone immer ramda underscore date-fns dayjs
luxon numeral validator joi yup zod ajv is-number kind-of is-buffer type-fest
event-stream left-pad is-odd is-even camelcase decamelize dedent execa
globby ignore fast-glob picomatch micromatch braces fill-range to-regex-range
resolve enhanced-resolve loader-utils schema-utils tapable acorn escodegen
estraverse esprima source-map source-map-support stack-trace serialize-javascript
node-gyp node-pre-gyp prebuild-install tar tar-fs unzipper adm-zip archiver
yauzl yazl minipass pacote npm-registry-fetch make-fetch-happen agentkeepalive
http-proxy http-proxy-middleware express-session connect-redis csurf
express-rate-limit compression serve-static send finalhandler router
path-to-regexp encodeurl escape-html parseurl range-parser content-type
content-disposition accepts negotiator vary etag fresh on-finished destroy
depd statuses http-errors setprototypeof toidentifier unpipe media-typer
type-is raw-body iconv-lite whatwg-url tr46 webidl-conversions punycode
"""

POPULAR_PYPI = """
requests urllib3 numpy pandas scipy matplotlib django flask fastapi sqlalchemy
pydantic click jinja2 werkzeug boto3 botocore six setuptools pip wheel certifi
charset-normalizer idna python-dateutil pytz pyyaml cryptography cffi pycparser
attrs packaging typing-extensions pytest tox coverage black flake8 mypy isort
pylint sphinx docutils markupsafe itsdangerous blinker gunicorn uvicorn
starlette httpx httpcore anyio sniffio h11 aiohttp celery redis pymongo
psycopg2 psycopg2-binary mysqlclient pillow opencv-python scikit-learn
tensorflow torch keras transformers tqdm rich colorama tabulate termcolor
protobuf grpcio paramiko fabric ansible docker kubernetes jsonschema
marshmallow arrow pendulum python-dotenv environs structlog loguru sentry-sdk
prometheus-client cachetools chardet decorator filelock frozenlist fsspec
greenlet importlib-metadata jmespath joblib lxml multidict nest-asyncio
oauthlib openpyxl platformdirs pluggy psutil pyarrow pyasn1 pygments pyjwt
pyparsing pytest-cov regex requests-oauthlib rsa s3transfer scramp soupsieve
sqlparse tenacity threadpoolctl tomli tornado traitlets virtualenv websocket-client
websockets wrapt xlrd yarl zipp beautifulsoup4 bs4 selenium scrapy notebook
jupyter ipython nbformat nbconvert plotly seaborn statsmodels sympy networkx
nltk spacy gensim xgboost lightgbm catboost shap optuna mlflow ray dask numba
cython pybind11 pytest-xdist hypothesis faker freezegun responses vcrpy
"""


def _words(blob: str) -> frozenset[str]:
    return frozenset(blob.split())


POPULAR = {
    "npm": _words(POPULAR_NPM),
    "pypi": _words(POPULAR_PYPI),
}

# Affixes attackers bolt onto a real name to look like an official variant.
AFFIXES = {
    "npm": ["js", "node", "nodejs", "npm", "core", "cli", "lib", "sdk", "official", "dev", "ts"],
    "pypi": ["py", "python", "python3", "lib", "sdk", "cli", "core", "official", "dev", "api"],
}

# Characters that render close enough to an ASCII letter to fool a reader.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "ο": "o", "α": "a", "ρ": "p", "ɡ": "g", "ᴉ": "i",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
}

# Paths whose appearance in an install script is the whole point of the attack.
CREDENTIAL_PATHS = [
    "~/.ssh", ".ssh/id_", "~/.aws", ".aws/credentials", "~/.npmrc", ".npmrc",
    "~/.docker/config", ".git-credentials", "~/.kube/config", ".pypirc",
    "id_rsa", "id_ed25519", "security find-generic-password", "login.keychain",
    "GITHUB_TOKEN", "NPM_TOKEN", "AWS_SECRET", "AWS_ACCESS_KEY",
    "/etc/shadow", "wallet.dat", "Local Storage/leveldb",
]
