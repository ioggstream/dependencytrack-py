import logging
from pathlib import Path

import yaml

try:
    import click
    import pandas as pd
except ImportError:
    print(
        """
Install the dependencies with:

pip install click pandas

"""
    )
import dependencytrack as dt

log = logging.getLogger(__name__)


@click.command()
@click.option(
    "--config-file",
    "-c",
    required=True,
    help="Path to dependencytrack config file",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.option("--vcs-domain", "-v", help="Git servers to track.", default="")
@click.option(
    "--internal-groups",
    "-i",
    default=tuple(),
    help="Dependencies in internal groups are recursively resolved"
    " ad DependencyTrack projects. E.g. -i org.example -i io.github",
    multiple=True,
)
@click.option("-o", "--output-file", required=True, help="Output file")
@click.option("-f", "--filter", default="", help="Filter project names")
@click.option(
    "--add-self-dependency",
    is_flag=True,
    default=False,
    help="Add to every project a component referencing the project purl.",
)
def main(
    config_file, output_file, internal_groups, vcs_domain, filter, add_self_dependency
):
    config = Path(config_file).expanduser().read_text()
    config = yaml.safe_load(config)
    client = dt.DependencyTrack(**config)

    df = pd.DataFrame(
        data=get_all_project_dependencies(
            client,
            filter=filter,
            internal_groups=internal_groups,
            vcs_domain=vcs_domain,
            add_self_dependency=add_self_dependency,
        )
    )
    df.to_csv(output_file)


def get_project_dependencies(
    project: dt.Project, vcs_domain: str = "", internal_groups: tuple = ()
):
    scm_url = [
        er.get("url", None)
        for er in project.data.get("externalReferences", [])
        if er.get("type", "").lower() == "vcs" and vcs_domain in er.get("url", "")
    ]
    scm_url = scm_url[0] if scm_url else None
    project_data = {
        "project_name": project.data["name"],
        "project_version": project.data["version"],
        "project_type": project.data.get("classifier"),
        "project_group": project.data.get("group"),
        "project_description": project.data.get("description"),
        "project_last_import": project.data["lastBomImport"],
        "project_scm": scm_url,
        "project_uuid": project.data["uuid"],
    }
    traversed = set()
    for dependency_data in yield_project_dependencies(
        project, traversed=traversed, internal_groups=internal_groups
    ):
        yield {**project_data, **dependency_data}


def yield_project_dependencies(
    project: dt.Project, traversed=None, internal_groups: tuple = ()
):
    client = project.client

    dependencies = project.component.list(fields=["purl", "name", "classifier", "uuid"])
    for dependency in dependencies:
        dependency_url = dependency.get("purl") or dependency.get("name")

        if dependency_url in traversed:
            continue
        traversed.add(dependency_url)
        yield {
            "dependency_url": dependency_url,
            "dependency_classifier": dependency["classifier"],
        }

        if any((x in dependency_url for x in internal_groups)):
            internal_components = client.component.identity.list(
                purl=dependency_url, fields=["purl", "project"]
            )
            internal_projects = [
                x["project"]["uuid"]
                for x in internal_components
                if x.get("project", {}).get("purl") == dependency_url
            ]
            for internal_project in internal_projects:
                yield from yield_project_dependencies(
                    client.project.get(internal_project),
                    traversed=traversed,
                    internal_groups=internal_groups,
                )


def get_all_project_dependencies(client: dt.DependencyTrack, **kwargs):
    add_self_dependency = kwargs.pop("add_self_dependency")
    if filter_ := kwargs.pop("filter"):
        filter_ = {"searchText": filter_}
    else:
        filter_ = {}
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
        ],
        **filter_,
    )

    for project in projects:
        project = client.project.get(project["uuid"])

        if project.data.get("purl") and add_self_dependency:
            # Add a self-indexing component to the project.
            has_self_component = [
                component
                for component in client.component.identity.list(purl=project["purl"])
                if component.get("project", {}).get("purl") == project["purl"]
            ]
            if not has_self_component:
                self_component = {
                    "name": project["name"],
                    "version": project["version"],
                    "group": project["group"],
                    "purl": project["purl"],
                    "classifier": project["classifier"],
                    "author": "Self-dependency added by report.py",
                }

                project.component.create(entry=self_component)

        yield from get_project_dependencies(project, **kwargs)


if __name__ == "__main__":
    main()
