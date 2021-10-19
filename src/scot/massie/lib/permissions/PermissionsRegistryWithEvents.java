package scot.massie.lib.permissions;

import scot.massie.lib.events.Event;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.ProtectedEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.permissions.events.args.*;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * <p>A {@link PermissionsRegistry permissions registry} with events for when the contents of the registry change.</p>
 *
 * @see scot.massie.lib.permissions.PermissionsRegistry
 * @param <ID>The type of the unique identifier used to represent users.
 */
public class PermissionsRegistryWithEvents<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    //region events
    //region internal events
    /**
     * Fired when a permission is assigned to something.
     */
    protected final InvokableEvent<PermissionAssignedEventArgs<ID>> permissionAssigned_internal = new SetEvent<>();

    /**
     * Fired when a permission is revoked from something.
     */
    protected final InvokableEvent<PermissionRevokedEventArgs<ID>> permissionRevoked_internal = new SetEvent<>();

    /**
     * Fired when a group is assigned to something.
     */
    protected final InvokableEvent<PermissionGroupAssignedEventArgs<ID>> groupAssigned_internal = new SetEvent<>();

    /**
     * Fired when a group is revoked from something.
     */
    protected final InvokableEvent<PermissionGroupRevokedEventArgs<ID>> groupRevoked_internal = new SetEvent<>();

    /**
     * Fired when the registry is cleared.
     */
    protected final InvokableEvent<PermissionsClearedEventArgs<ID>> cleared_internal = new SetEvent<>();

    /**
     * Fired when the registry's contents are replaced with the contents as loaded from a file.
     */
    protected final InvokableEvent<PermissionsLoadedEventArgs<ID>> loaded_internal = new SetEvent<>();

    /**
     * Fired when the contents of the permissions registry are changed.
     *
     * Fired when any of the following are fired:
     * <ul>
     *     <li>permissionAssigned_internal</li>
     *     <li>permissionRevoked_internal</li>
     *     <li>groupAssigned_internal</li>
     *     <li>groupRevoked_internal</li>
     *     <li>cleared_internal</li>
     *     <li>loaded_internal</li>
     * </ul>
     */
    protected final InvokableEvent<PermissionsChangedEventArgs<ID>> contentsChanged_internal = new SetEvent<>();
    {
        permissionAssigned_internal.register(contentsChanged_internal, args -> args);
        permissionRevoked_internal .register(contentsChanged_internal, args -> args);
        groupAssigned_internal     .register(contentsChanged_internal, args -> args);
        groupRevoked_internal      .register(contentsChanged_internal, args -> args);
        cleared_internal           .register(contentsChanged_internal, args -> args);
        loaded_internal            .register(contentsChanged_internal, args -> args);
    }
    //endregion

    //region public-facing events
    /**
     * Fired when a permission is assigned to something.
     */
    public final Event<PermissionAssignedEventArgs<ID>> permissionAssigned = new ProtectedEvent<>(permissionAssigned_internal);

    /**
     * Fired when a permission is revoked from something.
     */
    public final Event<PermissionRevokedEventArgs<ID>> permissionRevoked = new ProtectedEvent<>(permissionRevoked_internal);

    /**
     * Fired when a group is assigned to something.
     */
    public final Event<PermissionGroupAssignedEventArgs<ID>> groupAssigned = new ProtectedEvent<>(groupAssigned_internal);

    /**
     * Fired when a group is revoked from something.
     */
    public final Event<PermissionGroupRevokedEventArgs<ID>> groupRevoked = new ProtectedEvent<>(groupRevoked_internal);

    /**
     * Fired when the registry is cleared.
     */
    public final Event<PermissionsClearedEventArgs<ID>> cleared = new ProtectedEvent<>(cleared_internal);

    /**
     * Fired when the registry's contents are replaced with the contents as loaded from a file.
     */
    public final Event<PermissionsLoadedEventArgs<ID>> loaded = new ProtectedEvent<>(loaded_internal);

    /**
     * Fired when the contents of the permissions registry are changed.
     *
     * Fired when any of the following are fired:
     * <ul>
     *     <li>permissionAssigned</li>
     *     <li>permissionRevoked</li>
     *     <li>groupAssigned</li>
     *     <li>groupRevoked</li>
     *     <li>cleared</li>
     *     <li>loaded</li>
     * </ul>
     */
    public final Event<PermissionsChangedEventArgs<ID>> contentsChanged = new ProtectedEvent<>(contentsChanged_internal);
    //endregion
    //endregion

    //region initialisation
    /**
     * Creates a new permissions registry with the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString,
                                         Path usersFile,
                                         Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new permissions registry without the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }
    //endregion

    //region methods
    @Override
    public void assignUserPermission(ID userId, String permission)
    {
        super.assignUserPermission(userId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutUser(this, userId, permission));
    }

    @Override
    public void assignGroupPermission(String groupId, String permission)
    {
        super.assignGroupPermission(groupId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutGroup(this, groupId, permission));
    }

    @Override
    public void assignDefaultPermission(String permission)
    {
        super.assignDefaultPermission(permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutDefaultPermissions(this, permission));
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        Permission r = super.revokeUserPermission(userId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutUser(this, userId, permission, r));
        return r;
    }

    @Override
    public Permission revokeGroupPermission(String groupId, String permission)
    {
        Permission r = super.revokeGroupPermission(groupId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutGroup(this, groupId, permission, r));
        return r;
    }

    @Override
    public Permission revokeDefaultPermission(String permission)
    {
        Permission r = super.revokeDefaultPermission(permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutDefaultPermissions(this, permission, r));
        return r;
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        super.assignGroupToUser(userId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutUser(this, userId, groupIdBeingAssigned));
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        super.assignGroupToGroup(groupId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutGroup(this, groupId, groupIdBeingAssigned));
    }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    {
        super.assignDefaultGroup(groupIdBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutDefaultPermissions(this, groupIdBeingAssigned));
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromUser(userId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutUser(this, userId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromGroup(groupId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutGroup(this, groupId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    {
        boolean result = super.revokeDefaultGroup(groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutDefaultPermissions(this, groupIdBeingRevoked));
        return result;
    }

    @Override
    public void clear()
    {
        super.clear();
        cleared_internal.invoke(new PermissionsClearedEventArgs<>(this));
    }

    @Override
    public void load() throws IOException
    {
        super.load();
        loaded_internal.invoke(new PermissionsLoadedEventArgs<>(this));
    }
    //endregion
}
