package scot.massie.lib.permissions.decorators;

import scot.massie.lib.permissions.Permission;
import scot.massie.lib.permissions.PermissionStatus;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;
import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * <p>A {@link PermissionsRegistry permissions registry} decorator providing synchronous access.</p>
 * @see scot.massie.lib.permissions.PermissionsRegistry
 * @param <ID>The type of the unique identifier used to represent users.
 */
public final class ThreadsafePermissionsRegistry<ID extends Comparable<? super ID>>
        extends PermissionsRegistryDecorator<ID>
{
    /**
     * Creates a new threadsafe permissions registry, with the ability to save to/load from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public ThreadsafePermissionsRegistry(Function<ID, String> idToString,
                                         Function<String, ID> idFromString,
                                         Path usersFile,
                                         Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new threadsafe permissions registry, without the ability to save to/load from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    /**
     * Wraps an existing permissions registry in a threadsafe permissions registry, providing synchronous access to it.
     * @param inner The wrapped permissions registry.
     */
    public ThreadsafePermissionsRegistry(PermissionsRegistry<ID> inner)
    {
        super(inner.getIdToStringFunction(),
              inner.getIdFromStringFunction(),
              inner.getUsersFilePath(),
              inner.getGroupsFilePath());
    }

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.getUserPermissionStatus(userId, permission); }
    }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    {
        synchronized(inner)
        { return inner.getGroupPermissionStatus(groupName, permission); }
    }

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    {
        synchronized(inner)
        { return inner.getDefaultPermissionStatus(permission); }
    }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.getUserPermissionStatuses(userId, permissions); }
    }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    {
        synchronized(inner)
        { return inner.getUserPermissionStatuses(userId, permissions); }
    }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.getGroupPermissionStatuses(groupName, permissions); }
    }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    {
        synchronized(inner)
        { return inner.getGroupPermissionStatuses(groupName, permissions); }
    }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.getDefaultPermissionStatuses(permissions); }
    }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    {
        synchronized(inner)
        { return inner.getDefaultPermissionStatuses(permissions); }
    }

    @Override
    public void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException
    {
        synchronized(inner)
        { inner.assertUserHasPermission(userId, permission); }
    }

    @Override
    public void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException
    {
        synchronized(inner)
        { inner.assertGroupHasPermission(groupName, permission); }
    }

    @Override
    public void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException
    {
        synchronized(inner)
        { inner.assertIsDefaultPermission(permission); }
    }

    @Override
    public void assertUserHasAllPermissions(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    {
        synchronized(inner)
        { inner.assertUserHasAllPermissions(userId, permissions); }
    }

    @Override
    public void assertUserHasAllPermissions(ID userId, String... permissions) throws UserMissingPermissionException
    {
        synchronized(inner)
        { inner.assertUserHasAllPermissions(userId, permissions); }
    }

    @Override
    public void assertGroupHasAllPermissions(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    {
        synchronized(inner)
        { inner.assertGroupHasAllPermissions(groupName, permissions); }
    }

    @Override
    public void assertGroupHasAllPermissions(String groupName, String... permissions) throws GroupMissingPermissionException
    {
        synchronized(inner)
        { inner.assertGroupHasAllPermissions(groupName, permissions); }
    }

    @Override
    public void assertAllAreDefaultPermissions(Iterable<String> permissions) throws PermissionNotDefaultException
    {
        synchronized(inner)
        { inner.assertAllAreDefaultPermissions(permissions); }
    }

    @Override
    public void assertAllAreDefaultPermissions(String... permissions) throws PermissionNotDefaultException
    {
        synchronized(inner)
        { inner.assertAllAreDefaultPermissions(permissions); }
    }

    @Override
    public void assertUserHasAnyPermission(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    {
        synchronized(inner)
        { inner.assertUserHasAnyPermission(userId, permissions); }
    }

    @Override
    public void assertUserHasAnyPermission(ID userId, String... permissions) throws UserMissingPermissionException
    {
        synchronized(inner)
        { inner.assertUserHasAnyPermission(userId, permissions); }
    }

    @Override
    public void assertGroupHasAnyPermission(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    {
        synchronized(inner)
        { inner.assertGroupHasAnyPermission(groupName, permissions); }
    }

    @Override
    public void assertGroupHasAnyPermission(String groupName, String... permissions) throws GroupMissingPermissionException
    {
        synchronized(inner)
        { inner.assertGroupHasAnyPermission(groupName, permissions); }
    }

    @Override
    public void assertAnyAreDefaultPermission(Iterable<String> permissions) throws PermissionNotDefaultException
    {
        synchronized(inner)
        { inner.assertAnyAreDefaultPermission(permissions); }
    }

    @Override
    public void assertAnyAreDefaultPermission(String... permissions) throws PermissionNotDefaultException
    {
        synchronized(inner)
        { inner.assertAnyAreDefaultPermission(permissions); }
    }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.userHasPermission(userId, permission); }
    }

    @Override
    public boolean groupHasPermission(String groupName, String permission)
    {
        synchronized(inner)
        { return inner.groupHasPermission(groupName, permission); }
    }

    @Override
    public boolean isDefaultPermission(String permission)
    {
        synchronized(inner)
        { return inner.isDefaultPermission(permission); }
    }

    @Override
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.userHasAllPermissions(userId, permissions); }
    }

    @Override
    public boolean userHasAllPermissions(ID userId, String... permissions)
    {
        synchronized(inner)
        { return inner.userHasAllPermissions(userId, permissions); }
    }

    @Override
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.groupHasAllPermissions(groupName, permissions); }
    }

    @Override
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    {
        synchronized(inner)
        { return inner.groupHasAllPermissions(groupName, permissions); }
    }

    @Override
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.areAllDefaultPermissions(permissions); }
    }

    @Override
    public boolean areAllDefaultPermissions(String... permissions)
    {
        synchronized(inner)
        { return inner.areAllDefaultPermissions(permissions); }
    }

    @Override
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.userHasAnyPermissions(userId, permissions); }
    }

    @Override
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    {
        synchronized(inner)
        { return inner.userHasAnyPermissions(userId, permissions); }
    }

    @Override
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.groupHasAnyPermissions(groupName, permissions); }
    }

    @Override
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    {
        synchronized(inner)
        { return inner.groupHasAnyPermissions(groupName, permissions); }
    }

    @Override
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.anyAreDefaultPermissions(permissions); }
    }

    @Override
    public boolean anyAreDefaultPermissions(String... permissions)
    {
        synchronized(inner)
        { return inner.anyAreDefaultPermissions(permissions); }
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.userHasAnySubPermissionOf(userId, permission); }
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.userHasAnySubPermissionOf(userId, permissions); }
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    {
        synchronized(inner)
        { return inner.userHasAnySubPermissionOf(userId, permissions); }
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    {
        synchronized(inner)
        { return inner.groupHasAnySubPermissionOf(groupId, permission); }
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.groupHasAnySubPermissionOf(groupId, permissions); }
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    {
        synchronized(inner)
        { return inner.groupHasAnySubPermissionOf(groupId, permissions); }
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    {
        synchronized(inner)
        { return inner.isOrAnySubPermissionOfIsDefault(permission); }
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    {
        synchronized(inner)
        { return inner.isOrAnySubPermissionOfIsDefault(permissions); }
    }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    {
        synchronized(inner)
        { return inner.isOrAnySubPermissionOfIsDefault(permissions); }
    }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.getUserPermissionArg(userId, permission); }
    }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    {
        synchronized(inner)
        { return inner.getGroupPermissionArg(groupId, permission); }
    }

    @Override
    public String getDefaultPermissionArg(String permission)
    {
        synchronized(inner)
        { return inner.getDefaultPermissionArg(permission); }
    }

    @Override
    public boolean userHasGroup(ID userId, String groupName)
    {
        synchronized(inner)
        { return inner.userHasGroup(userId, groupName); }
    }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    {
        synchronized(inner)
        { return inner.groupExtendsFromGroup(groupId, superGroupName); }
    }

    @Override
    public boolean isDefaultGroup(String groupId)
    {
        synchronized(inner)
        { return inner.isDefaultGroup(groupId); }
    }

    @Override
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    {
        synchronized(inner)
        { return inner.userHasAllGroups(userId, groupNames); }
    }

    @Override
    public boolean userHasAllGroups(ID userId, String... groupNames)
    {
        synchronized(inner)
        { return inner.userHasAllGroups(userId, groupNames); }
    }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    {
        synchronized(inner)
        { return inner.groupExtendsFromAllGroups(groupName, superGroupNames); }
    }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    {
        synchronized(inner)
        { return inner.groupExtendsFromAllGroups(groupName, superGroupNames); }
    }

    @Override
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    {
        synchronized(inner)
        { return inner.areAllDefaultGroups(groupNames); }
    }

    @Override
    public boolean areAllDefaultGroups(String... groupNames)
    {
        synchronized(inner)
        { return inner.areAllDefaultGroups(groupNames); }
    }

    @Override
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    {
        synchronized(inner)
        { return inner.userHasAnyGroups(userId, groupNames); }
    }

    @Override
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    {
        synchronized(inner)
        { return inner.userHasAnyGroups(userId, groupNames); }
    }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    {
        synchronized(inner)
        { return inner.groupExtendsFromAnyGroups(groupName, superGroupNames); }
    }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    {
        synchronized(inner)
        { return inner.groupExtendsFromAnyGroups(groupName, superGroupNames); }
    }

    @Override
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    {
        synchronized(inner)
        { return inner.anyAreDefaultGroups(groupNames); }
    }

    @Override
    public boolean anyAreDefaultGroups(String... groupNames)
    {
        synchronized(inner)
        { return inner.anyAreDefaultGroups(groupNames); }
    }

    @Override
    public boolean hasBeenDifferentiatedFromFiles()
    {
        synchronized(inner)
        { return inner.hasBeenDifferentiatedFromFiles(); }
    }

    @Override
    public Collection<String> getGroupNames()
    {
        synchronized(inner)
        { return inner.getGroupNames(); }
    }

    @Override
    public Collection<ID> getUsers()
    {
        synchronized(inner)
        { return inner.getUsers(); }
    }

    @Override
    public List<String> getUserPermissions(ID userId)
    {
        synchronized(inner)
        { return inner.getUserPermissions(userId); }
    }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    {
        synchronized(inner)
        { return inner.getGroupPermissions(groupdId); }
    }

    @Override
    public List<String> getDefaultPermissions()
    {
        synchronized(inner)
        { return inner.getDefaultPermissions(); }
    }

    @Override
    public Collection<PermissionStatus> getAllUserPermissionStatuses(ID userId)
    {
        synchronized(inner)
        { return inner.getAllUserPermissionStatuses(userId); }
    }

    @Override
    public Collection<PermissionStatus> getAllGroupPermissionStatuses(String groupName)
    {
        synchronized(inner)
        { return inner.getAllGroupPermissionStatuses(groupName); }
    }

    @Override
    public Collection<PermissionStatus> getAllDefaultPermissionStatuses()
    {
        synchronized(inner)
        { return inner.getAllDefaultPermissionStatuses(); }
    }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    {
        synchronized(inner)
        { return inner.getGroupsOfUser(userId); }
    }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    {
        synchronized(inner)
        { return inner.getGroupsOfGroup(groupId); }
    }

    @Override
    public List<String> getDefaultGroups()
    {
        synchronized(inner)
        { return inner.getDefaultGroups(); }
    }

    @Override
    public Permission assignUserPermission(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.assignUserPermission(userId, permission); }
    }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    {
        synchronized(inner)
        { return inner.assignGroupPermission(groupId, permission); }
    }

    @Override
    public Permission assignDefaultPermission(String permission)
    {
        synchronized(inner)
        { return inner.assignDefaultPermission(permission); }
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        synchronized(inner)
        { return inner.revokeUserPermission(userId, permission); }
    }

    @Override
    public Permission revokeGroupPermission(String groupId, String permission)
    {
        synchronized(inner)
        { return inner.revokeGroupPermission(groupId, permission); }
    }

    @Override
    public Permission revokeDefaultPermission(String permission)
    {
        synchronized(inner)
        { return inner.revokeDefaultPermission(permission); }
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        synchronized(inner)
        { inner.assignGroupToUser(userId, groupIdBeingAssigned); }
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        synchronized(inner)
        { inner.assignGroupToGroup(groupId, groupIdBeingAssigned); }
    }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    {
        synchronized(inner)
        { inner.assignDefaultGroup(groupIdBeingAssigned); }
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        synchronized(inner)
        { return inner.revokeGroupFromUser(userId, groupIdBeingRevoked); }
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        synchronized(inner)
        { return inner.revokeGroupFromGroup(groupId, groupIdBeingRevoked); }
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    {
        synchronized(inner)
        { return inner.revokeDefaultGroup(groupIdBeingRevoked); }
    }

    @Override
    public void clear()
    {
        synchronized(inner)
        { inner.clear(); }
    }

    @Override
    public String usersToSaveString()
    {
        synchronized(inner)
        { return inner.usersToSaveString(); }
    }

    @Override
    public String groupsToSaveString()
    {
        synchronized(inner)
        { return inner.groupsToSaveString(); }
    }

    @Override
    public void save() throws IOException
    {
        synchronized(inner)
        { inner.save(); }
    }

    @Override
    public void load() throws IOException
    {
        synchronized(inner)
        { inner.load(); }
    }

    @Override
    public int hashCode()
    {
        synchronized(inner)
        { return inner.hashCode(); }
    }

    @Override
    public boolean equals(Object obj)
    {
        synchronized(inner)
        { return inner.equals(obj); }
    }

    @Override
    public String toString()
    {
        synchronized(inner)
        { return inner.toString(); }
    }
}
