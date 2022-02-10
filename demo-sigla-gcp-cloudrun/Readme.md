# Deploy della soluzione

Accedere alla Cloud Shell di GCP e autenticarsi tramite il comando
```console
gcloud auth login
```

La soluzione dovrà essere erogata su un progetto vuoto già esistente, indicare quindi l'id del progetto e configurarlo come variabile d'ambiente
```console
export project_id=[project_id]
```
Settare il contesto col progetto GCP scelto
```console
gcloud config set project $project_id
```

Assicurarsi che tutti gli script siano eseguibili
```console
chmod +x *.sh
```

E infine lanciare il comando di creazione
```console
./start-demo.sh
```

## Provalo su Google Cloud
[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/consiglionazionaledellericerche/sigla-ng.git&cloudshell_workspace=./demo-sigla-gcp-cloudrun&cloudshell_print=guide.txt&shellonly=true)