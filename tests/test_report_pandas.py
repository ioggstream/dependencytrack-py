import uuid
from pathlib import Path

import pytest
import yaml

from dependencytrack import DependencyTrack

try:
    import pandas as pd
except ImportError:
    pytestmark = pytest.mark.skip("all tests still WIP")


@pytest.fixture
def dt():
    config = yaml.safe_load(Path(".dependencytrack-py.yaml").read_text())
    return DependencyTrack(config)


def test_get_all_project_dependencies(dt):
    df = pd.DataFrame(data=get_all_project_dependencies(dt))
    df.to_csv(f"deleteme-{uuid.uuid4()}.csv")


def get_all_project_dependencies(client):
    projects = client.project.list(
        fields=[
            "uuid",
            "name",
            "version",
            "group",
            "classifier",
            "lastBomImport",
            "externalReferences",
            "description",
        ]
    )

    for project in projects[:10]:
        scm_url = [
            er.get("url", None)
            for er in project.get("externalReferences", [])
            if er.get("type", "").lower() == "vcs"
        ]
        scm_url = scm_url[0] if scm_url else None
        dependencies = client.component.project.get(
            project["uuid"], fields=["purl", "classifier"]
        )
        for dependency in dependencies:
            dependency_url = dependency.get("purl") or dependency.get("name")
            yield {
                "project_name": project["name"],
                "project_version": project["version"],
                "project_type": project.get("classifier"),
                "project_group": project.get("group"),
                "project_description": project.get("description"),
                "project_last_import": project["lastBomImport"],
                "project_scm": scm_url,
                "project_uuid": project["uuid"],
                "dependency_url": dependency_url,
                "dependency_classifier": dependency["classifier"],
            }
