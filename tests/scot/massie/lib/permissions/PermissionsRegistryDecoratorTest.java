package scot.massie.lib.permissions;

/**
 * Base test class for permissions registry decorators.
 * @implNote Assumes that decorator decorates an instance of {@link GroupMapPermissionsRegistry} - if this is not the
 *           case, {@link #createUser(PermissionsRegistryDecorator, String)},
 *           {@link #createGroup(PermissionsRegistryDecorator, String)},
 *           {@link #createGroup(PermissionsRegistryDecorator, String, int)}, and
 *           {@link #createGroup(PermissionsRegistryDecorator, String, double)} should be overridden with versions of
 *           those methods to perform relevant specified action on the specific implementation, with the use of
 *           {@link #getInner(PermissionsRegistryDecorator)} to access the wrapped permissions registry if required.
 * @param <TPReg> The type of the permissions registry decorator being tested.
 */
public abstract class PermissionsRegistryDecoratorTest<TPReg extends PermissionsRegistryDecorator<String>>
        extends PermissionsRegistryTest<TPReg>
{
    protected PermissionsRegistry<String> getInner(TPReg reg)
    { return reg.inner; }

    @Override
    protected void createUser(TPReg reg, String userId)
    { ((GroupMapPermissionsRegistry<String>)getInner(reg)).getUserPermissionsGroupOrNew(userId); }

    @Override
    protected void createGroup(TPReg reg, String groupName)
    { ((GroupMapPermissionsRegistry<String>)getInner(reg)).getGroupPermissionsGroupOrNew(groupName); }

    @Override
    protected void createGroup(TPReg reg, String groupName, int priority)
    { ((GroupMapPermissionsRegistry<String>)getInner(reg)).getGroupPermissionsGroupOrNew(groupName, priority); }

    @Override
    protected void createGroup(TPReg reg, String groupName, double priority)
    { ((GroupMapPermissionsRegistry<String>)getInner(reg)).getGroupPermissionsGroupOrNew(groupName, priority); }
}
