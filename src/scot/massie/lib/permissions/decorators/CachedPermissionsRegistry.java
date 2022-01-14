package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.PermissionStatus;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;
import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.nio.file.Path;
import java.util.Map;
import java.util.function.Function;

public class CachedPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    public CachedPermissionsRegistry(Function<ID, String> idToString,
                                     Function<String, ID> idFromString,
                                     Path usersFile,
                                     Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public CachedPermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    public CachedPermissionsRegistry(PermissionsRegistry<ID> inner)
    { super(inner); }

    public void invalidateCache()
    {
        // TO DO: Write
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getUserPermissionStatus(userId, permission);
    }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getGroupPermissionStatus(groupName, permission);
    }

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getDefaultPermissionStatus(permission);
    }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getUserPermissionStatuses(userId, permissions);
    }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getUserPermissionStatuses(userId, permissions);
    }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getGroupPermissionStatuses(groupName, permissions);
    }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getGroupPermissionStatuses(groupName, permissions);
    }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getDefaultPermissionStatuses(permissions);
    }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getDefaultPermissionStatuses(permissions);
    }

    @Override
    public void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertUserHasPermission(userId, permission);
    }

    @Override
    public void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertGroupHasPermission(groupName, permission);
    }

    @Override
    public void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertIsDefaultPermission(permission);
    }

    @Override
    public void assertUserHasAllPermissions(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertUserHasAllPermissions(userId, permissions);
    }

    @Override
    public void assertUserHasAllPermissions(ID userId, String... permissions) throws UserMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertUserHasAllPermissions(userId, permissions);
    }

    @Override
    public void assertGroupHasAllPermissions(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertGroupHasAllPermissions(groupName, permissions);
    }

    @Override
    public void assertGroupHasAllPermissions(String groupName, String... permissions) throws GroupMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertGroupHasAllPermissions(groupName, permissions);
    }

    @Override
    public void assertAllAreDefaultPermissions(Iterable<String> permissions) throws PermissionNotDefaultException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertAllAreDefaultPermissions(permissions);
    }

    @Override
    public void assertAllAreDefaultPermissions(String... permissions) throws PermissionNotDefaultException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertAllAreDefaultPermissions(permissions);
    }

    @Override
    public void assertUserHasAnyPermission(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertUserHasAnyPermission(userId, permissions);
    }

    @Override
    public void assertUserHasAnyPermission(ID userId, String... permissions) throws UserMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertUserHasAnyPermission(userId, permissions);
    }

    @Override
    public void assertGroupHasAnyPermission(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertGroupHasAnyPermission(groupName, permissions);
    }

    @Override
    public void assertGroupHasAnyPermission(String groupName, String... permissions) throws GroupMissingPermissionException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertGroupHasAnyPermission(groupName, permissions);
    }

    @Override
    public void assertAnyAreDefaultPermission(Iterable<String> permissions) throws PermissionNotDefaultException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertAnyAreDefaultPermission(permissions);
    }

    @Override
    public void assertAnyAreDefaultPermission(String... permissions) throws PermissionNotDefaultException
    {
        // TO DO: Replace with calls that check caches.
        inner.assertAnyAreDefaultPermission(permissions);
    }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasPermission(userId, permission);
    }

    @Override
    public boolean groupHasPermission(String groupName, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasPermission(groupName, permission);
    }

    @Override
    public boolean isDefaultPermission(String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.isDefaultPermission(permission);
    }

    @Override
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAllPermissions(userId, permissions);
    }

    @Override
    public boolean userHasAllPermissions(ID userId, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAllPermissions(userId, permissions);
    }

    @Override
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAllPermissions(groupName, permissions);
    }

    @Override
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAllPermissions(groupName, permissions);
    }

    @Override
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.areAllDefaultPermissions(permissions);
    }

    @Override
    public boolean areAllDefaultPermissions(String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.areAllDefaultPermissions(permissions);
    }

    @Override
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnyPermissions(userId, permissions);
    }

    @Override
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnyPermissions(userId, permissions);
    }

    @Override
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAnyPermissions(groupName, permissions);
    }

    @Override
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAnyPermissions(groupName, permissions);
    }

    @Override
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.anyAreDefaultPermissions(permissions);
    }

    @Override
    public boolean anyAreDefaultPermissions(String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.anyAreDefaultPermissions(permissions);
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnySubPermissionOf(userId, permission);
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnySubPermissionOf(userId, permissions);
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnySubPermissionOf(userId, permissions);
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAnySubPermissionOf(groupId, permission);
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAnySubPermissionOf(groupId, permissions);
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupHasAnySubPermissionOf(groupId, permissions);
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.isOrAnySubPermissionOfIsDefault(permission);
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.isOrAnySubPermissionOfIsDefault(permissions);
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    {
        // TO DO: Replace with calls that check caches.
        return inner.isOrAnySubPermissionOfIsDefault(permissions);
    }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getUserPermissionArg(userId, permission);
    }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getGroupPermissionArg(groupId, permission);
    }

    @Override
    public String getDefaultPermissionArg(String permission)
    {
        // TO DO: Replace with calls that check caches.
        return inner.getDefaultPermissionArg(permission);
    }

    @Override
    public boolean userHasGroup(ID userId, String groupName)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasGroup(userId, groupName);
    }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupExtendsFromGroup(groupId, superGroupName);
    }

    @Override
    public boolean isDefaultGroup(String groupId)
    {
        // TO DO: Replace with calls that check caches.
        return inner.isDefaultGroup(groupId);
    }

    @Override
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAllGroups(userId, groupNames);
    }

    @Override
    public boolean userHasAllGroups(ID userId, String... groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAllGroups(userId, groupNames);
    }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupExtendsFromAllGroups(groupName, superGroupNames);
    }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupExtendsFromAllGroups(groupName, superGroupNames);
    }

    @Override
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.areAllDefaultGroups(groupNames);
    }

    @Override
    public boolean areAllDefaultGroups(String... groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.areAllDefaultGroups(groupNames);
    }

    @Override
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnyGroups(userId, groupNames);
    }

    @Override
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.userHasAnyGroups(userId, groupNames);
    }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupExtendsFromAnyGroups(groupName, superGroupNames);
    }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.groupExtendsFromAnyGroups(groupName, superGroupNames);
    }

    @Override
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.anyAreDefaultGroups(groupNames);
    }

    @Override
    public boolean anyAreDefaultGroups(String... groupNames)
    {
        // TO DO: Replace with calls that check caches.
        return inner.anyAreDefaultGroups(groupNames);
    }
}
