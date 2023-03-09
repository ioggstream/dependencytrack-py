import uuid
from pathlib import Path

import pytest
import yaml

from dependencytrack import DependencyTrack, Project


@pytest.fixture
def dt():
    config = Path("~/.dependencytrack-py-test.yaml").expanduser().read_text()
    config = yaml.safe_load(config)
    return DependencyTrack(**config)


@pytest.fixture
def complex_project(dt):
    sbom_json = Path("tests/sbom.json")
    sbom = yaml.safe_load(sbom_json.read_text())
    project = Project.from_sbom(sbom)
    project["name"] = f"deleteme-{uuid.uuid4()}"
    ret = dt.project.create(entry=project)
    assert "uuid" in ret

    yield ret

    dt.project.get(ret["uuid"]).delete()
    assert dt.project.get(ret["uuid"]) is None


@pytest.fixture
def sample_project(dt):
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
    project = dt.project.create(entry=project).data
    dt.component.project
    yield project
    dt.project.delete(project["uuid"])
