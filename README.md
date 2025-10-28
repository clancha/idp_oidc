# Identity Provider with OIDC

## How to run

### How to build the docker image
```
cd idp_oidc
docker build -t <image_name> .
```

### How to run the container
```
cd idp_oidc
docker run -e <env_variable_1=value> -e <env_variable_2=value> -p 8080:8080 <image_name>
```

### Global variables

#### There are some env variables to cofigure, you can see them in `idp_oidc/oidc_app/config.py`
* WSCD_URL -> Mandatory
* API_ENROLLMENT -> `/api/mceliece/enrollment` by default
* API_VERIFICATI -> `/api/mceliece/verification` by default
