package scot.massie.lib.permissions.decorators;

import scot.massie.lib.events.Event;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.ProtectedEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.permissions.Permission;
import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;
import scot.massie.lib.permissions.events.args.*;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

/**
 * <p>A {@link PermissionsRegistry permissions registry} decorator with events for when the contents of the registry
 * change.</p>
 *
 * @apiNote If used in conjunction with {@link ThreadsafePermissionsRegistry}, this should wrap an instance of that
 *          class, rather than vice versa - so that events are fired outwith that class' synchronisation locks. As
 *          ThreadsafePermissionsRegistry doesn't add any of its own methods, this also means not having to keep two
 *          separate decorated references to your {@link PermissionsRegistry}.
 * @apiNote If this decorates another decorator, events do not fire for modifications made to the permissions registry
 *          by an enclosed decorator, only for modifications made through this one. (including by decorators enclosing
 *          this one)
 * @see PermissionsRegistry
 * @param <ID> The type of the unique identifier used to represent users.
 */
public class PermissionsRegistryWithEvents<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    //region Events
    //region Internal events
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

    //region Public-facing events
    /**
     * Fired when a permission is assigned to something.
     */
    public final Event<PermissionAssignedEventArgs<ID>> permissionAssigned
            = new ProtectedEvent<>(permissionAssigned_internal);

    /**
     * Fired when a permission is revoked from something.
     */
    public final Event<PermissionRevokedEventArgs<ID>> permissionRevoked
            = new ProtectedEvent<>(permissionRevoked_internal);

    /**
     * Fired when a group is assigned to something.
     */
    public final Event<PermissionGroupAssignedEventArgs<ID>> groupAssigned
            = new ProtectedEvent<>(groupAssigned_internal);

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
    public final Event<PermissionsChangedEventArgs<ID>> contentsChanged
            = new ProtectedEvent<>(contentsChanged_internal);
    //endregion
    //endregion

    //region Initialisation
    /**
     * Creates a new permissions registry with events, with the ability to save to/load from files. This is the
     * equivalent of passing a new instance of {@link GroupMapPermissionsRegistry} created with the given arguments into
     * {@link #PermissionsRegistryWithEvents(PermissionsRegistry)}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString, Path usersFile, Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new permissions registry with events, without the ability to save to/load from files. This is the
     * equivalent of passing a new instance of {@link GroupMapPermissionsRegistry} created with the given arguments into
     * {@link #PermissionsRegistryWithEvents(PermissionsRegistry)}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    /**
     * Wraps an existing permissions registry in a permissions registry with events, which will fire as appropriate.
     * @param inner The wrapped permissions registry.
     */
    public PermissionsRegistryWithEvents(PermissionsRegistry<ID> inner)
    { super(inner); }
    //endregion

    //region Methods
    @Override
    public void absorb(PermissionsRegistry<ID> other)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void removeContentsOf(PermissionsRegistry<ID> other)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public Permission assignUserPermission(ID userId, String permission)
    {
        Permission oldValue = super.assignUserPermission(userId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutUser(this,
                                                                                    userId,
                                                                                    permission,
                                                                                    oldValue));
        return oldValue;
    }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    {
        Permission oldValue = super.assignGroupPermission(groupId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutGroup(this,
                                                                                     groupId,
                                                                                     permission,
                                                                                     oldValue));
        return oldValue;
    }

    @Override
    public Permission assignDefaultPermission(String permission)
    {
        Permission oldValue = super.assignDefaultPermission(permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutDefaultPermissions(this,
                                                                                                  permission,
                                                                                                  oldValue));
        return oldValue;
    }

    @Override
    public void assignUserPermissions(ID userId, List<String> permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignUserPermissions(ID userId, String[] permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupPermissions(String groupName, List<String> permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupPermissions(String groupName, String[] permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignDefaultPermissions(List<String> permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignDefaultPermissions(String[] permissions)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        Permission r = super.revokeUserPermission(userId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutUser(this, userId, permission, r));
        return r;
    }

    @Override
    public Permission revokeGroupPermission(String groupeName, String permission)
    {
        Permission r = super.revokeGroupPermission(groupeName, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutGroup(this, groupeName, permission, r));
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
    public void revokeAllUserPermissions(ID userId)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void revokeAllGroupPermissions(String groupName)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void revokeAllDefaultPermissions()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupToUser(ID userId, String groupNameBeingAssigned)
    {
        super.assignGroupToUser(userId, groupNameBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutUser(this,
                                                                                    userId,
                                                                                    groupNameBeingAssigned));
    }

    @Override
    public void assignGroupToGroup(String groupName, String groupNameBeingAssigned)
    {
        super.assignGroupToGroup(groupName, groupNameBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutGroup(this,
                                                                                     groupName,
                                                                                     groupNameBeingAssigned));
    }

    @Override
    public void assignDefaultGroup(String groupNameBeingAssigned)
    {
        super.assignDefaultGroup(groupNameBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutDefaultPermissions(this, groupNameBeingAssigned));
    }

    @Override
    public void assignGroupsToUser(ID userId, List<String> groupNamesBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupsToUser(ID userId, String[] groupNamesBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupsToGroup(String groupName, List<String> groupNamesBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignGroupsToGroup(String groupName, String[] groupNamesBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignDefaultGroups(List<String> groupNameBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void assignDefaultGroups(String[] groupNameBeingAssigned)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupNameBeingRevoked)
    {
        boolean result = super.revokeGroupFromUser(userId, groupNameBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutUser(this, userId, groupNameBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupName, String groupNameBeingRevoked)
    {
        boolean result = super.revokeGroupFromGroup(groupName, groupNameBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutGroup(this, groupName, groupNameBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupNameBeingRevoked)
    {
        boolean result = super.revokeDefaultGroup(groupNameBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutDefaultPermissions(this,
                                                                                                groupNameBeingRevoked));
        return result;
    }

    @Override
    public void revokeAllGroupsFromUser(ID userId)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void revokeAllGroupsFromGroup(String groupName)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void revokeAllDefaultGroups()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clear()
    {
        super.clear();
        cleared_internal.invoke(new PermissionsClearedEventArgs<>(this));
    }

    @Override
    public void clearUsers()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearUsers(Collection<ID> userIds)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearUsers(ID[] userIds)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearUser(ID userId)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearGroups()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearGroups(Collection<String> groupNames)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearGroups(String[] groupNames)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearGroup(String groupName)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void clearDefaults()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void load() throws IOException
    {
        super.load();
        loaded_internal.invoke(new PermissionsLoadedEventArgs<>(this));
    }
    //endregion
}
