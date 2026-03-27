from django.db import migrations

def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")

    try:
        pm = PythonModule.objects.get(
            module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
        )
    except PythonModule.DoesNotExist:
        return

    params_to_fix = Parameter.objects.filter(
        python_module=pm, name__in=["published", "metadata"]
    )

    for param in params_to_fix:
        param.required = False
        param.save()
        
        # Update existing configurations to be None by default
        PluginConfig.objects.filter(parameter=param).update(value=None)

def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")

    try:
        pm = PythonModule.objects.get(
            module="misp.MISP", base_path="api_app.analyzers_manager.observable_analyzers"
        )
    except PythonModule.DoesNotExist:
        return

    params_to_revert = Parameter.objects.filter(
        python_module=pm, name__in=["published", "metadata"]
    )

    for param in params_to_revert:
        param.required = True
        param.save()
        
        # Revert existing configurations to False
        PluginConfig.objects.filter(parameter=param).update(value=False)

class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0175_analyzer_config_cleanbrowsing_malicious_detector"), # Last migration in api_app
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"), # Last migration in analyzers_manager
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
