import uuid
from pathlib import Path

import pytest
import yaml

from dependencytrack import DependencyTrack


@pytest.fixture
def dt():
    config = yaml.safe_load(Path(".dependencytrack-py.yaml").read_text())
    return DependencyTrack(**config)


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
    yield project
    dt.project.delete(project["uuid"])


def test_project_not_found(dt):
    MISSING = "c554d5f2-ad9e-4d2b-be66-19a81f4bf3af"
    assert dt.project.get(MISSING) is None


def test_list_projects(dt):
    ret = dt.project.list()
    assert len(ret) > 0

    project = ret[0]
    assert dt.project.get(project["uuid"])["name"] == project["name"]


def test_list_components(dt):
    uuid = dt.project.list()[0]["uuid"]
    project = dt.project.get(uuid)

    # The actual API layout is messy since
    #  it mixes the project and component.
    components = dt.component.project.get(project["uuid"])
    assert len(components)


def test_create_project(dt):
    project = {
        "name": "deleteme",
        "version": f"{uuid.uuid4()}",
    }
    other = {
        "group": "io.github",
        "classifier": "APPLICATION",
        "tags": [{"name": "fake-tag-1"}, {"name": "fake-tag-2"}],
    }
    ret = dt.project.create(entry=dict(project, **other))
    assert "uuid" in ret
    dt.project.get(ret["uuid"]).delete()
    assert dt.project.get(ret["uuid"]) is None


def test_project_property(dt, sample_project):
    project = dt.project.get(sample_project["uuid"])
    properties = project.property.list()
    assert len(properties) == 2


def test_tag(dt):
    ret = dt.project.tag.get("fake-tag-1")
    assert len(ret) > 0


def test_sbom_put(dt, sample_project):
    import base64
    from pathlib import Path

    sbom_json = Path(__file__).parent / "sbom.json"
    sbom = {
        "projectName": sample_project["name"],
        "projectVersion": sample_project["version"] + "-sbom",
        "autoCreate": True,
        "bom": base64.b64encode(sbom_json.read_bytes()).decode(),
    }
    ret = dt.bom.upload(sbom)
    assert "token" in ret
