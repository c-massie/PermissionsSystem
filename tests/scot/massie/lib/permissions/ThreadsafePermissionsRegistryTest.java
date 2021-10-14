package scot.massie.lib.permissions;

public class ThreadsafePermissionsRegistryTest extends PermissionsRegistryTest
{
    @Override
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new ThreadsafePermissionsRegistry<>(s -> s, s -> s); }
}
