# Dependency-Track

A simple python library to interact with the OWASP Dependency-Track API.

## Installation

```bash
pip install git+https://github.com/ioggstream/dependencytrack-py
```

## Usage

See [dependencytrack-py-sample.yaml](dependencytrack-py-sample.yaml) for a sample configuration file.

```python
from dependency_track import DependencyTrack

client = DependencyTrack(baseurl=..., token=...,)

# Get all projects
projects = client.project.list()

# Create a project
entry = {
    "name": "My Project",
    "version": "1.0.0",
    "description": "My Project Description",
    "classifier": "LIBRARY",
}
project = client.project.create(entry=entry)

# Get a specific project
project = client.project.get(uuid=project["uuid"])
print(project["name"], project["version"])

# Upload a bom to a project.
bom_payload = client.prepare_bom(
    sbom_path="sbom.json",
    project_uuid=project["uuid"],
)
client.bom.upload(bom_payload)

# Get all components
components = client.component.project.get(a_project["uuid"])
assert len(components) > 0
component = components[0]
print(component)
```

See [tests](tests/test_report_pandas.py) for a more complete example
of creating reports using this library.

## Contributing

Please, see [CONTRIBUTING.md](CONTRIBUTING.md) for more details on:

- using [pre-commit](CONTRIBUTING.md#pre-commit);
- following the git flow and making good [pull requests](CONTRIBUTING.md#making-a-pr).

## Using this repository

You can create new projects starting from this repository,
so you can use a consistent CI and checks for different projects.

Besides all the explanations in the [CONTRIBUTING.md](CONTRIBUTING.md) file, you can use the docker-compose file
(e.g. if you prefer to use docker instead of installing the tools locally)

```bash
docker-compose run pre-commit
```
