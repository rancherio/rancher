import pytest
from .common import *  # NOQA

project = {}
project_detail = {"c0_id": None, "c1_id": None, "c2_id": None,
                  "p0_id": None, "p1_id": None, "p2_id": None,
                  "p_client0": None, "namespace0": None, "cluster0": None, "project0": None,
                  "p_client1": None, "namespace1": None, "cluster1": None, "project1": None,
                  "p_client2": None, "namespace2": None, "cluster2": None, "project2": None}

global_client = {"client": None, "cluster_count": False}
answer_105version = {
    "values": {
        "defaultImage": "true",
        "externalDatabase.database": "",
        "externalDatabase.host": "",
        "externalDatabase.password": "",
        "externalDatabase.port": "3306",
        "externalDatabase.user": "",
        "image.repository": "bitnami/wordpress",
        "image.tag": "4.9.4",
        "ingress.enabled": "true",
        "ingress.hosts[0].name": "xip.io",
        "mariadb.enabled": "true",
        "mariadb.image.repository": "bitnami/mariadb",
        "mariadb.image.tag": "10.1.32",
        "mariadb.mariadbDatabase": "wordpress",
        "mariadb.mariadbPassword": "",
        "mariadb.mariadbUser": "wordpress",
        "mariadb.persistence.enabled": "false",
        "mariadb.persistence.existingClaim": "",
        "mariadb.persistence.size": "8Gi",
        "mariadb.persistence.storageClass": "",
        "nodePorts.http": "",
        "nodePorts.https": "",
        "persistence.enabled": "false",
        "persistence.existingClaim": "",
        "persistence.size": "10Gi",
        "persistence.storageClass": "",
        "serviceType": "NodePort",
        "wordpressEmail": "user@example.com",
        "wordpressPassword": "",
        "wordpressUsername": "user"
    }
}

answer = {
    "values": {
        "defaultImage": "true",
        "externalDatabase.database": "",
        "externalDatabase.host": "",
        "externalDatabase.password": "",
        "externalDatabase.port": "3306",
        "externalDatabase.user": "",
        "image.repository": "bitnami/wordpress",
        "image.tag": "4.9.8-debian-9",
        "ingress.enabled": "true",
        "ingress.hosts[0].name": "xip.io",
        "mariadb.db.name": "wordpress",
        "mariadb.db.user": "wordpress",
        "mariadb.enabled": "true",
        "mariadb.image.repository": "bitnami/mariadb",
        "mariadb.image.tag": "10.1.35-debian-9",
        "mariadb.mariadbPassword": "",
        "mariadb.master.persistence.enabled": "false",
        "mariadb.master.persistence.existingClaim": "",
        "mariadb.master.persistence.size": "8Gi",
        "mariadb.master.persistence.storageClass": "",
        "nodePorts.http": "",
        "nodePorts.https": "",
        "persistence.enabled": "false",
        "persistence.size": "10Gi",
        "persistence.storageClass": "",
        "serviceType": "NodePort",
        "wordpressEmail": "user@example.com",
        "wordpressPassword": "",
        "wordpressUsername": "user"
    }
}

grafana_answers = {
    "values": {
        "adminPassword": "",
        "adminUser": "admin",
        "auth.anonymous.enabled": "true",
        "defaultImage": "true",
        "grafanaWatcher.image.repository": "appropriate/curl",
        "grafanaWatcher.image.tag": "latest",
        "image.repository": "grafana/grafana",
        "image.tag": "5.0.0",
        "ingress.enabled": "true",
        "ingress.hosts[0]": "xip.io",
        "persistence.enabled": "false",
        "persistence.size": "8Gi",
        "persistence.storageClass": "",
        "service.nodePort": "",
        "service.type": "NodePort"
    }
}

mysql_answers = {
    "values": {
        "defaultImage": "true",
        "image": "mysql",
        "imageTag": "5.7.14",
        "mysqlDatabase": "admin",
        "mysqlPassword": "",
        "mysqlUser": "admin",
        "persistence.enabled": "false",
        "persistence.size": "8Gi",
        "persistence.storageClass": "",
        "service.nodePort": "",
        "service.port": "3306",
        "service.type": "ClusterIP"
    }
}


mysql_new_answers = {
    "values": {
        "defaultImage": "true",
        "image": "mysql",
        "imageTag": "5.7.14",
        "mysqlDatabase": "admin",
        "mysqlPassword": "",
        "mysqlUser": "admin1234",
        "persistence.enabled": "false",
        "persistence.size": "8Gi",
        "persistence.storageClass": "",
        "service.nodePort": "",
        "service.port": "3306",
        "service.type": "ClusterIP"
    }
}


ROLES = ["project-member"]
TEMP_VER = "cattle-global-data:library-wordpress-2.1.10"
NEW_VER = "cattle-global-data:library-wordpress-2.1.12"


NEW_UPGRADE = {
    'rollingUpdate':
        {'batchSize': 1,
         'interval': 20,
         'type': '/v3/schemas/rollingUpdate'},
        'type': '/v3/schemas/upgradeStrategy'}
MYSQL_TEMP_VER = "cattle-global-data:library-mysql-0.3.7"
MYSQL_NEW_VER = "cattle-global-data:library-mysql-0.3.8"
GRAFANA_VER = "cattle-global-data:library-grafana-0.0.31"


# def test_multi_cluster_rolling_upgrade():
#     assert_if_valid_cluster_count()
#     targets = []
#     for projectid in project:
#         targets.append({"projectId": projectid, "type": "target"})
#     client = global_client["client"]
#     multiclusterapp = client.create_multiClusterApp(
#                                                     templateVersionId=MYSQL_TEMP_VER,
#                                                     targets=targets,
#                                                     roles=["cluster-owner"],
#                                                     name=random_name(),
#                                                     answers=[mysql_answers],
#                                                     upgradeStrategy=NEW_UPGRADE)
#     multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
#     project_client1 = project_detail["p_client0"]
#     project_client2 = project_detail["p_client1"]
#     app = multiclusterapp.targets[0].projectId.split(":")
#     app1id = app[1] + ":" + multiclusterapp.targets[0].appId
#     app2 = multiclusterapp.targets[1].projectId.split(":")
#     app2id = app2[1] + ":" + multiclusterapp.targets[1].appId
#     multiclusterapp = client.update(multiclusterapp,
#                                     roles=["cluster-owner"],
#                                     answers=[mysql_new_answers])
#     multiclusterapp = client.reload(multiclusterapp)
#     start = time.time()
#     upgraded = False
#     # assert apps have different states and answers
#     while time.time()-start < 30 or upgraded == False:
#         upgraded = return_application_status_and_upgrade(
#             project_client1, app1id, project_client2, app2id)
#         time.sleep(.1)
#     assert upgraded == True, "did not upgrade correctly"
#     time.sleep(20)
#     # since one has updated, asserts that both apps are in teh same state
#     while time.time()-start < 100 or upgraded == True:
#         upgraded = return_application_status_and_upgrade(
#             project_client1, app1id, project_client2, app2id)
#         time.sleep(.1)
#     assert upgraded == False, "did not upgrade correctly"
#     validate_multi_cluster_app_cluster(multiclusterapp)
#     delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_template_upgrade():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=MYSQL_TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[mysql_answers])
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster(multiclusterapp)
    multiclusterapp = client.update(multiclusterapp,
                                    roles=ROLES,
                                    templateVersionId=MYSQL_NEW_VER)
    multiclusterapp = client.reload(multiclusterapp)
    validate_multi_cluster_app_cluster(multiclusterapp)
    validate_app_upgrade_mca(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_template_rollback():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=MYSQL_TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[mysql_answers])
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster(multiclusterapp)
    first_id = multiclusterapp["status"]["revisionId"]
    assert multiclusterapp.templateVersionId == MYSQL_TEMP_VER
    multiclusterapp = client.update(multiclusterapp,
                                    roles=ROLES,
                                    templateVersionId=MYSQL_NEW_VER)
    multiclusterapp = client.reload(multiclusterapp)
    assert multiclusterapp.templateVersionId == MYSQL_NEW_VER
    validate_app_upgrade_mca(multiclusterapp)
    client.action(obj=multiclusterapp,
                  action_name='rollback',
                  revisionId=first_id)
    multiclusterapp = client.reload(multiclusterapp)
    assert multiclusterapp.templateVersionId == MYSQL_TEMP_VER
    validate_app_upgrade_mca(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_upgrade_and_add_target():
    assert_if_valid_cluster_count()
    project_id = project_detail["p0_id"]
    targets = [{"projectId": project_id, "type": "target"}]
    project_id_2 = project_detail["p1_id"]
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=MYSQL_TEMP_VER,
                                                    roles=ROLES,
                                                    targets=targets,
                                                    name=random_name(),
                                                    answers=[mysql_answers],
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    uuid = multiclusterapp.uuid
    name = multiclusterapp.name
    assert len(client.list_multiClusterApp(
        uuid=uuid, name=name).data[0]["targets"]) == 1, \
        "did not start with 1 target"
    client.action(obj=multiclusterapp, action_name="addProjects",
                  projects=[project_id_2])
    multiclusterapp = client.reload(multiclusterapp)
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    assert len(client.list_multiClusterApp(
        uuid=uuid, name=name).data[0]["targets"]) == 2, "did not add target"
    validate_multi_cluster_app_cluster(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_project_answer_override():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=MYSQL_TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[mysql_answers],
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    mysql_override = [{
        "values": {
            "defaultImage": "true",
            "image": "mysql",
            "imageTag": "5.7.14",
            "mysqlDatabase": "admin",
            "mysqlPassword": "",
            "mysqlUser": "admin",
            "persistence.enabled": "false",
            "persistence.size": "8Gi",
            "persistence.storageClass": "",
            "service.nodePort": "",
            "service.port": "3306",
            "service.type": "ClusterIP"
        }
    },
        {
            "clusterId": None,
            "projectId": project_detail["p0_id"],
            "type": "/v3/schemas/answer",
            "values": {
                "mysqlUser": "test_override"
            }
        }]
    multiclusterapp = client.update(multiclusterapp,
                                    roles=ROLES,
                                    answers=mysql_override
                                    )
    multiclusterapp = client.reload(multiclusterapp)
    for i in range(0, len(multiclusterapp.targets)):
        project_client = project_detail["p_client"+str(i)]
        app = multiclusterapp.targets[i].projectId.split(":")
        appid = app[1] + ":" + multiclusterapp.targets[i].appId
        validate_answer_override(project_client, appid, i)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_create():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[answer])
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_upgrade_and_delete_target():
    assert_if_valid_cluster_count()
    project_id = project_detail["p0_id"]
    targets = []
    for project_id in project:
        targets.append({"projectId": project_id, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=TEMP_VER,
                                                    roles=ROLES,
                                                    targets=targets,
                                                    name=random_name(),
                                                    answers=[answer],
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    uuid = multiclusterapp.uuid
    name = multiclusterapp.name
    assert len(client.list_multiClusterApp(
        uuid=uuid, name=name).data[0]["targets"]) == 2, \
        "did not start with 2 targets"
    project_client = project_detail["p_client0"]
    app = multiclusterapp.targets[0].projectId.split(":")
    app1id = app[1] + ":" + multiclusterapp.targets[0].appId
    client.action(obj=multiclusterapp, action_name="removeProjects",
                  projects=[project_id])
    multiclusterapp = client.reload(multiclusterapp)
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    assert len(multiclusterapp["targets"]) == 1, "did not delete target"
    validate_app_deletion(project_client, app1id)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_role_change():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    original_role = ["project-member"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=GRAFANA_VER,
                                                    targets=targets,
                                                    roles=original_role,
                                                    name=random_name(),
                                                    answers=[grafana_answers])
    try:
        multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    except Exception:
        print("expected failure as project member")
        pass  # expected fail
    multiclusterapp = client.update(multiclusterapp, roles=["cluster-owner"])
    client.reload(multiclusterapp)
    validate_multi_cluster_app_cluster(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_app_delete():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[answer])
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_all_answer_override():
    assert_if_valid_cluster_count()
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    client = global_client["client"]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[answer],
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    new_answers = answer
    new_answers["values"]["wordpressUsername"] = "test_all_answers_override"
    multiclusterapp = client.update(multiclusterapp,
                                    roles=ROLES,
                                    answers=[new_answers])
    multiclusterapp = client.reload(multiclusterapp)
    validate_all_answer_override_mca(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_app_edit():
    assert_if_valid_cluster_count()
    client = global_client["client"]
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    temp_ver = "cattle-global-data:library-wordpress-1.0.5"
    multiclusterapp = client.create_multiClusterApp(templateVersionId=temp_ver,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[answer_105version]
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    # verify if this app is available in the cluster/project
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    temp_ver = "cattle-global-data:library-wordpress-2.1.10"
    multiclusterapp = client.update(multiclusterapp,
                                    uuid=multiclusterapp.uuid,
                                    templateVersionId=temp_ver,
                                    roles=ROLES,
                                    answers=[answer])
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    # verify if this app is available in the cluster/project
    # check if correct field was changed
    validate_multi_cluster_app_cluster_wordpress(multiclusterapp)
    delete_multi_cluster_app(multiclusterapp)


def test_multi_cluster_cluster_answer_override():
    assert_if_valid_cluster_count()
    client, clusters = get_admin_client_and_cluster_mcapp()
    cluster1 = clusters[0]
    p3, ns3 = create_project_and_ns(ADMIN_TOKEN, cluster1, "test_3")
    p_client2 = get_project_client_for_token(p3, ADMIN_TOKEN)
    project_detail["c2_id"] = cluster1.id
    project_detail["namespace2"] = ns3
    project_detail["p2_id"] = p3.id
    project_detail["p_client2"] = p_client2
    project_detail["cluster2"] = cluster1
    project_detail["project2"] = p3
    project[p3.id] = project_detail
    client = global_client["client"]
    targets = []
    for projectid in project:
        targets.append({"projectId": projectid, "type": "target"})
    mysql_override = [{
        "values": {
            "defaultImage": "true",
            "image": "mysql",
            "imageTag": "5.7.14",
            "mysqlDatabase": "admin",
            "mysqlPassword": "",
            "mysqlUser": "admin",
            "persistence.enabled": "false",
            "persistence.size": "8Gi",
            "persistence.storageClass": "",
            "service.nodePort": "",
            "service.port": "3306",
            "service.type": "ClusterIP"
        }
    },
        {
            "clusterId": project_detail["c0_id"],
            "projectId": None,
            "type": "/v3/schemas/answer",
            "values": {
                "mysqlUser": "test_override"
            }
        }]
    multiclusterapp = client.create_multiClusterApp(templateVersionId=MYSQL_TEMP_VER,
                                                    targets=targets,
                                                    roles=ROLES,
                                                    name=random_name(),
                                                    answers=[mysql_answers],
                                                    )
    multiclusterapp = wait_for_mcapp_to_active(client, multiclusterapp)
    multiclusterapp = client.update(multiclusterapp,
                                    roles=ROLES,
                                    answers=mysql_override
                                    )
    multiclusterapp = client.reload(multiclusterapp)
    for i in range(0, len(multiclusterapp.targets)):
        project_client = project_detail["p_client" + str(i)]
        app = multiclusterapp.targets[i].projectId.split(":")
        appid = app[1] + ":" + multiclusterapp.targets[i].appId
        validate_answer_override(project_client, appid, i)
    client_admin = get_admin_client()
    client_admin.delete(p3, ns3, p_client2)
    delete_multi_cluster_app(multiclusterapp)


@pytest.fixture(scope='module', autouse="True")
def create_project_client(request):
    client, clusters = get_admin_client_and_cluster_mcapp()
    if len(clusters) > 1:
        global_client["cluster_count"] = True
    assert_if_valid_cluster_count()
    cluster1 = clusters[0]
    cluster2 = clusters[1]
    p1, ns1 = create_project_and_ns(ADMIN_TOKEN, cluster1, "test_1")
    p_client1 = get_project_client_for_token(p1, ADMIN_TOKEN)
    p2, ns2 = create_project_and_ns(ADMIN_TOKEN, cluster2, "test_2")
    p_client2 = get_project_client_for_token(p2, ADMIN_TOKEN)
    project_detail["c0_id"] = cluster1.id
    project_detail["p0_id"] = p1.id
    project_detail["namespace0"] = ns1
    project_detail["p_client0"] = p_client1
    project_detail["cluster0"] = cluster1
    project_detail["project0"] = p1
    project[p1.id] = project_detail
    project_detail["c1_id"] = cluster2.id
    project_detail["namespace1"] = ns2
    project_detail["p1_id"] = p2.id
    project_detail["p_client1"] = p_client2
    project_detail["cluster1"] = cluster2
    project_detail["project1"] = p2
    project[p2.id] = project_detail
    global_client["client"] = client

    def fin():
        client_admin = get_admin_client()
        client_admin.delete(p1, ns1, p_client1)
        client_admin.delete(p2, ns2, p_client2)

    request.addfinalizer(fin)


def assert_if_valid_cluster_count():
    assert global_client["cluster_count"], \
        "Setup Failure. Tests require at least 2 clusters"


def validate_multi_cluster_app_cluster_wordpress(multiclusterapp):
    for i in range(1, len(multiclusterapp.targets)):
        app_id = multiclusterapp.targets[i].appId
        assert app_id is not None, "app_id is None"
        project_client = project_detail["p_client"+str(i)]
        wait_for_app_to_active(project_client, app_id)
        validate_response_app_endpoint(project_client, app_id)


def validate_multi_cluster_app_cluster(multiclusterapp):
    for i in range(1, len(multiclusterapp.targets)):
        app_id = multiclusterapp.targets[i].appId
        assert app_id is not None, "app_id is None"
        project_client = project_detail["p_client"+str(i)]
        wait_for_app_to_active(project_client, app_id)


def get_admin_client_and_cluster_mcapp():
    clusters = []
    client = get_admin_client()
    if CLUSTER_NAME != "" and CLUSTER_NAME_2 != "":
        assert len(client.list_cluster(name=CLUSTER_NAME).data) != 0, \
            "Cluster is not available: %r" % CLUSTER_NAME
        assert len(client.list_cluster(name=CLUSTER_NAME_2).data) != 0, \
            "Cluster is not available: %r" % CLUSTER_NAME_2
        clusters.append(client.list_cluster(name=CLUSTER_NAME).data[0])
        clusters.append(client.list_cluster(name=CLUSTER_NAME_2).data[0])
    else:
        clusters = client.list_cluster().data
    return client, clusters


def delete_multi_cluster_app(multiclusterapp):
    client = global_client["client"]
    uuid = multiclusterapp.uuid
    name = multiclusterapp.name
    client.delete(multiclusterapp)
    mcapps = client.list_multiClusterApp(uuid=uuid, name=name).data
    assert len(mcapps) == 0, "Multi Cluster App is not deleted"


def validate_app_version(project_client, multiclusterapp, app_id):
    temp_version = multiclusterapp.templateVersionId
    app = temp_version.split(":")[1].split("-")
    mcapp_template_version = "catalog://?catalog=" + app[0] + \
                             "&template=" + app[1] + "&version=" + app[2]
    app_template_version = \
        project_client.list_app(name=app_id).data[0].externalId
    assert mcapp_template_version == app_template_version, \
        "App Id is different from the Multi cluster app id"


def return_application_status_and_upgrade(client1, app_id1, client2, app_id2):
    app_data1 = client1.list_app(id=app_id1).data
    application1 = app_data1[0]
    app_data2 = client2.list_app(id=app_id2).data
    application2 = app_data2[0]
    a = application1.state == "active" \
        and application1.answers["mysqlUser"] == "admin1234"
    b = application2.state == "active" \
        and application2.answers["mysqlUser"] == "admin1234"
    return a == True and b != True


def validate_app_upgrade_mca(multiclusterapp):
    for i in range(0, len(multiclusterapp.targets)):
        project_client = project_detail["p_client" + str(i)]
        app = multiclusterapp.targets[0].projectId.split(":")
        appid = app[1] + ":" + multiclusterapp.targets[i].appId
        temp_version = multiclusterapp.templateVersionId
        app = temp_version.split(":")[1].split("-")
        mcapp_template_version = "catalog://?catalog=" + app[0] + \
                                 "&template=" + app[1] + "&version=" \
                                 + app[2]
        app_template_version = \
            project_client.list_app(id=appid).data[0].externalId
        assert mcapp_template_version == app_template_version, \
            "App Id is different from the Multi cluster app id"


def validate_deletion_mca(multiclusterapp):
    for i in range(0, len(multiclusterapp.targets)):
        app_id = multiclusterapp.targets[i].appId
        assert app_id is not None, "app_id is None"
        project_client = project_detail["p_client"+str(i)]
        app = multiclusterapp.targets[i].projectId.split(":")
        app1id = app[1] + ":" + multiclusterapp.targets[i].appId
        validate_app_deletion(project_client, app1id)


def validate_all_answer_override_mca(multiclusterapp):
    for i in range(0, len(multiclusterapp.targets)):
        project_client = project_detail["p_client" + str(i)]
        app = multiclusterapp.targets[0].projectId.split(":")
        appid = app[1] + ":" + multiclusterapp.targets[i].appId
        hold = multiclusterapp['answers'][0]
        val = hold["values"]
        app_answers = \
            project_client.list_app(id=appid).data[0].answers
        assert str(val) == str(app_answers), \
            "App answers are different than the Multi cluster answers"


def validate_answer_override(project_client, appid, i):
    app_answers = project_client.list_app(id=appid).data[0].answers
    start = time.time()
    if i == 0:
        while app_answers.get("mysqlUser") != "test_override":
            if time.time()-start > 120:
                assert False, "timed out waiting for answer override"
            time.sleep(1)
            app_answers = project_client.list_app(id=appid).data[0].answers
    elif i == 1:
        assert app_answers.get("mysqlUser") == "admin", \
            "answers should not have changed"
    elif i == 2:
        while app_answers.get("mysqlUser") != "test_override":
            if time.time() - start > 120:
                assert False, "timed out waiting for answer override"
            time.sleep(1)
            app_answers = project_client.list_app(id=appid).data[0].answers
