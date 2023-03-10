import uuid
from pathlib import Path

import pytest
import yaml

import dependencytrack as dt
from dependencytrack import DependencyTrack, Project


@pytest.fixture
def dt_client():
    config = Path("~/.dependencytrack-py-test.yaml").expanduser().read_text()
    config = yaml.safe_load(config)
    return DependencyTrack(**config)


@pytest.fixture
def complex_project(dt_client):
    sbom_json = Path("tests/sbom.json")
    sbom = yaml.safe_load(sbom_json.read_text())
    project = Project.from_sbom(sbom)
    project["name"] = f"deleteme-{uuid.uuid4()}"
    ret = dt_client.project.create(entry=project)
    assert "uuid" in ret

    yield ret

    dt_client.project.get(ret["uuid"]).delete()
    with pytest.raises(dt.exc.NotFound):
        dt_client.project.get(ret["uuid"])


@pytest.fixture
def sample_project(dt_client):
    project = {
        "name": "deleteme",
        "version": f"{uuid.uuid4()}",
        "group": "io.github",
        "purl": "pkg:maven/io.github/dependencytrack-py@0.0.1",
        "classifier": "APPLICATION",
        "tags": [{"name": "fake-tag-1"}, {"name": "fake-tag-2"}],
        "properties": [
            {
                "propertyName": "fake-key-1",
                "propertyValue": "fake-value-1",
                "propertyType": "STRING",
                "groupName": "fake-group-1",
            },
            {
                "groupName": "fake-group-1",
                "propertyName": "fake-key-2",
                "propertyValue": "fake-value-2",
                "propertyType": "STRING",
            },
        ],
        "description": "This is a fake project.",
        "active": True,
    }
    project = dt_client.project.create(entry=project).data
    dt_client.component.project
    yield project
    dt_client.project.delete(project["uuid"])
