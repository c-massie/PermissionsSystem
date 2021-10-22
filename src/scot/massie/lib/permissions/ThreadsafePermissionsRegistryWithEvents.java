package scot.massie.lib.permissions;

import scot.massie.lib.permissions.events.args.PermissionAssignedEventArgs;
import scot.massie.lib.permissions.events.args.PermissionGroupAssignedEventArgs;
import scot.massie.lib.permissions.events.args.PermissionGroupRevokedEventArgs;
import scot.massie.lib.permissions.events.args.PermissionRevokedEventArgs;
import scot.massie.lib.permissions.events.args.PermissionsClearedEventArgs;
import scot.massie.lib.permissions.events.args.PermissionsLoadedEventArgs;
import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

public final class ThreadsafePermissionsRegistryWithEvents<ID extends Comparable<? super ID>>
        extends PermissionsRegistryWithEvents<ID>
{
    protected final ThreadsafePermissionsRegistry<ID> inner;

    //region initialisation
    public ThreadsafePermissionsRegistryWithEvents(Function<ID, String> idToString,
                                                   Function<String, ID> idFromString,
                                                   Path usersFile,
                                                   Path groupsFile)
    {
        super(idToString, idFromString, usersFile, groupsFile);
        inner = new ThreadsafePermissionsRegistry<>(idToString, idFromString, usersFile, groupsFile);
    }

    public ThreadsafePermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString)
    {
        super(idToString, idFromString);
        inner = new ThreadsafePermissionsRegistry<>(idToString, idFromString);
    }
    //endregion

    //region PermissionsRegistry methods
    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return inner.getUserPermissionStatus(userId, permission); }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupId, String permission)
    { return inner.getGroupPermissionStatus(groupId, permission); }

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { return inner.getDefaultPermissionStatus(permission); }

    @Override
    public void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException
    { inner.assertUserHasPermission(userId, permission); }

    @Override
    public void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException
    { inner.assertGroupHasPermission(groupName, permission); }

    @Override
    public void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException
    { inner.assertIsDefaultPermission(permission); }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { return inner.userHasPermission(userId, permission); }

    @Override
    public boolean groupHasPermission(String groupId, String permission)
    { return inner.groupHasPermission(groupId, permission); }

    @Override
    public boolean isDefaultPermission(String permission)
    { return inner.isDefaultPermission(permission); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return inner.userHasAnySubPermissionOf(userId, permission); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { return inner.groupHasAnySubPermissionOf(groupId, permission); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { return inner.isOrAnySubPermissionOfIsDefault(permission); }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    { return inner.getUserPermissionArg(userId, permission); }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    { return inner.getGroupPermissionArg(groupId, permission); }

    @Override
    public String getDefaultPermissionArg(String permission)
    { return inner.getDefaultPermissionArg(permission); }

    @Override
    public boolean userHasGroup(ID userId, String groupId)
    { return inner.userHasGroup(userId, groupId); }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    { return inner.groupExtendsFromGroup(groupId, superGroupId); }

    @Override
    public boolean isDefaultGroup(String groupId)
    { return inner.isDefaultGroup(groupId); }

    @Override
    public boolean hasBeenDifferentiatedFromFiles()
    { return inner.hasBeenDifferentiatedFromFiles(); }

    @Override
    public Collection<String> getGroupNames()
    { return inner.getGroupNames(); }

    @Override
    public Collection<ID> getUsers()
    { return inner.getUsers(); }

    @Override
    public List<String> getUserPermissions(ID userId)
    { return inner.getUserPermissions(userId); }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    { return inner.getGroupPermissions(groupdId); }

    @Override
    public List<String> getDefaultPermissions()
    { return inner.getDefaultPermissions(); }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    { return inner.getGroupsOfUser(userId); }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    { return inner.getGroupsOfGroup(groupId); }

    @Override
    public List<String> getDefaultGroups()
    { return inner.getDefaultGroups(); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupId)
    { return inner.getGroupPermissionsGroupOrNew(groupId); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupId, long priority)
    { return inner.getGroupPermissionsGroupOrNew(groupId, priority); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupId, double priority)
    { return inner.getGroupPermissionsGroupOrNew(groupId, priority); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupId, String priorityAsString)
            throws InvalidPriorityException
    { return inner.getGroupPermissionsGroupOrNew(groupId, priorityAsString); }

    @Override
    PermissionGroup getGroupPermissionsGroupFromSaveString(String saveString)
    { return inner.getGroupPermissionsGroupFromSaveString(saveString); }

    @Override
    PermissionGroup getUserPermissionsGroupOrNew(ID userId)
    { return inner.getUserPermissionsGroupOrNew(userId); }

    @Override
    PermissionGroup getUserPermissionsGroupFromSaveString(String saveString)
    { return inner.getUserPermissionsGroupFromSaveString(saveString); }

    @Override
    public Permission assignUserPermission(ID userId, String permission)
    {
        Permission oldValue = inner.assignUserPermission(userId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutUser(this,
                                                                                    userId,
                                                                                    permission,
                                                                                    oldValue));
        return oldValue;
    }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    {
        Permission oldValue = inner.assignGroupPermission(groupId, permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutGroup(this,
                                                                                     groupId,
                                                                                     permission,
                                                                                     oldValue));
        return oldValue;
    }

    @Override
    public Permission assignDefaultPermission(String permission)
    {
        Permission oldValue = inner.assignDefaultPermission(permission);
        permissionAssigned_internal.invoke(PermissionAssignedEventArgs.newAboutDefaultPermissions(this,
                                                                                                  permission,
                                                                                                  oldValue));
        return oldValue;
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        Permission result = inner.revokeUserPermission(userId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutUser(this, userId, permission, result));
        return result;
    }

    @Override
    public Permission revokeGroupPermission(String groupId, String permission)
    {
        Permission result = inner.revokeGroupPermission(groupId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutGroup(this, groupId, permission, result));
        return result;
    }

    @Override
    public Permission revokeDefaultPermission(String permission)
    {
        Permission r = inner.revokeDefaultPermission(permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutDefaultPermissions(this, permission, r));
        return r;
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        inner.assignGroupToUser(userId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutUser(this,
                                                                                    userId,
                                                                                    groupIdBeingAssigned));
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        inner.assignGroupToGroup(groupId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutGroup(this,
                                                                                     groupId,
                                                                                     groupIdBeingAssigned));
    }

    @Override
    public void assignDefaultGroup(String groupId)
    {
        inner.assignDefaultGroup(groupId);
        groupAssigned_internal.invoke(PermissionGroupAssignedEventArgs.newAboutDefaultPermissions(this,
                                                                                                  groupId));
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        boolean result = inner.revokeGroupFromUser(userId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutUser(this, userId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        boolean result = inner.revokeGroupFromGroup(groupId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutGroup(this, groupId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    {
        boolean result = inner.revokeDefaultGroup(groupIdBeingRevoked);
        groupRevoked_internal.invoke(PermissionGroupRevokedEventArgs.newAboutDefaultPermissions(this,
                                                                                                groupIdBeingRevoked));
        return result;
    }

    @Override
    public void clear()
    {
        inner.clear();
        cleared_internal.invoke(new PermissionsClearedEventArgs<>(this));
    }

    @Override
    public String usersToSaveString()
    { return inner.usersToSaveString(); }

    @Override
    public String groupsToSaveString()
    { return inner.groupsToSaveString(); }

    @Override
    public void save() throws IOException
    { inner.save(); }

    @Override
    public void load() throws IOException
    {
        inner.load();
        loaded_internal.invoke(new PermissionsLoadedEventArgs<>(this));
    }
    //endregion
}
