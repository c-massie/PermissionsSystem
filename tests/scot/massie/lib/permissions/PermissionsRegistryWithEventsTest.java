package scot.massie.lib.permissions;

public class PermissionsRegistryWithEventsTest extends PermissionsRegistryTest
{
    @Override
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistryWithEvents<>(s -> s, s -> s); }
}
