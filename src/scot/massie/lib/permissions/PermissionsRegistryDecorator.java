package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Base class for decorators of {@link PermissionsRegistry}.
 * @param <ID> The user ID type of the permissions registry being decorated.
 */
public class PermissionsRegistryDecorator<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    //region Instance fields
    /**
     * The permissions registry being decorated.
     */
    protected final PermissionsRegistry<ID> inner;
    //endregion

    //region Initialisation
    /**
     * Creates a new decorator, decorating a fresh instance of {@link PermissionsRegistry}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public PermissionsRegistryDecorator(Function<ID, String> idToString,
                                        Function<String, ID> idFromString,
                                        Path usersFile,
                                        Path groupsFile)
    {
        super(idToString, idFromString, usersFile, groupsFile);
        this.inner = new PermissionsRegistry<>(idToString, idFromString, usersFile, groupsFile);
    }

    /**
     * Creates a new decorator, decorating a fresh instance of {@link PermissionsRegistry}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistryDecorator(Function<ID, String> idToString, Function<String, ID> idFromString)
    {
        super(idToString, idFromString);
        this.inner = new PermissionsRegistry<>(idToString, idFromString);
    }

    /**
     * Creates a new decorator, decorating the given instance of {@link PermissionsRegistry}.
     * @param inner The instance of {@link PermissionsRegistry} to decorate.
     */
    public PermissionsRegistryDecorator(PermissionsRegistry<ID> inner)
    {
        super(inner.getIdToStringFunction(),
              inner.getIdFromStringFunction(),
              inner.getUsersFilePath(),
              inner.getGroupsFilePath());

        this.inner = inner;
    }
    //endregion

    //region Methods
    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return inner.getUserPermissionStatus(userId, permission); }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    { return inner.getGroupPermissionStatus(groupName, permission); }

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { return inner.getDefaultPermissionStatus(permission); }

    @Override
    protected PermissionStatus getPermissionStatus(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { return inner.getPermissionStatus(permGroup, permission, deferToDefault); }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    { return inner.getUserPermissionStatuses(userId, permissions); }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    { return inner.getUserPermissionStatuses(userId, permissions); }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    { return inner.getGroupPermissionStatuses(groupName, permissions); }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    { return inner.getGroupPermissionStatuses(groupName, permissions); }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    { return inner.getDefaultPermissionStatuses(permissions); }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    { return inner.getDefaultPermissionStatuses(permissions); }

    @Override
    protected Map<String, PermissionStatus> getPermissionStatuses(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    { return inner.getPermissionStatuses(permGroup, permissions, deferToDefault); }

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
    public void assertUserHasAllPermissions(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    { inner.assertUserHasAllPermissions(userId, permissions); }

    @Override
    public void assertUserHasAllPermissions(ID userId, String... permissions) throws UserMissingPermissionException
    { inner.assertUserHasAllPermissions(userId, permissions); }

    @Override
    public void assertGroupHasAllPermissions(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    { inner.assertGroupHasAllPermissions(groupName, permissions); }

    @Override
    public void assertGroupHasAllPermissions(String groupName, String... permissions) throws GroupMissingPermissionException
    { inner.assertGroupHasAllPermissions(groupName, permissions); }

    @Override
    public void assertAllAreDefaultPermissions(Iterable<String> permissions) throws PermissionNotDefaultException
    { inner.assertAllAreDefaultPermissions(permissions); }

    @Override
    public void assertAllAreDefaultPermissions(String... permissions) throws PermissionNotDefaultException
    { inner.assertAllAreDefaultPermissions(permissions); }

    @Override
    public void assertUserHasAnyPermission(ID userId, Iterable<String> permissions) throws UserMissingPermissionException
    { inner.assertUserHasAnyPermission(userId, permissions); }

    @Override
    public void assertUserHasAnyPermission(ID userId, String... permissions) throws UserMissingPermissionException
    { inner.assertUserHasAnyPermission(userId, permissions); }

    @Override
    public void assertGroupHasAnyPermission(String groupName, Iterable<String> permissions) throws GroupMissingPermissionException
    { inner.assertGroupHasAnyPermission(groupName, permissions); }

    @Override
    public void assertGroupHasAnyPermission(String groupName, String... permissions) throws GroupMissingPermissionException
    { inner.assertGroupHasAnyPermission(groupName, permissions); }

    @Override
    public void assertAnyAreDefaultPermission(Iterable<String> permissions) throws PermissionNotDefaultException
    { inner.assertAnyAreDefaultPermission(permissions); }

    @Override
    public void assertAnyAreDefaultPermission(String... permissions) throws PermissionNotDefaultException
    { inner.assertAnyAreDefaultPermission(permissions); }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { return inner.userHasPermission(userId, permission); }

    @Override
    public boolean groupHasPermission(String groupName, String permission)
    { return inner.groupHasPermission(groupName, permission); }

    @Override
    public boolean isDefaultPermission(String permission)
    { return inner.isDefaultPermission(permission); }

    @Override
    protected boolean hasPermission(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { return inner.hasPermission(permGroup, permission, deferToDefault); }

    @Override
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    { return inner.userHasAllPermissions(userId, permissions); }

    @Override
    public boolean userHasAllPermissions(ID userId, String... permissions)
    { return inner.userHasAllPermissions(userId, permissions); }

    @Override
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    { return inner.groupHasAllPermissions(groupName, permissions); }

    @Override
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    { return inner.groupHasAllPermissions(groupName, permissions); }

    @Override
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    { return inner.areAllDefaultPermissions(permissions); }

    @Override
    public boolean areAllDefaultPermissions(String... permissions)
    { return inner.areAllDefaultPermissions(permissions); }

    @Override
    protected boolean hasAllPermissions(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    { return inner.hasAllPermissions(permGroup, permissions, deferToDefault); }

    @Override
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    { return inner.userHasAnyPermissions(userId, permissions); }

    @Override
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    { return inner.userHasAnyPermissions(userId, permissions); }

    @Override
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    { return inner.groupHasAnyPermissions(groupName, permissions); }

    @Override
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    { return inner.groupHasAnyPermissions(groupName, permissions); }

    @Override
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    { return inner.anyAreDefaultPermissions(permissions); }

    @Override
    public boolean anyAreDefaultPermissions(String... permissions)
    { return inner.anyAreDefaultPermissions(permissions); }

    @Override
    protected boolean hasAnyPermissions(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    { return inner.hasAnyPermissions(permGroup, permissions, deferToDefault); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return inner.userHasAnySubPermissionOf(userId, permission); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    { return inner.userHasAnySubPermissionOf(userId, permissions); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    { return inner.userHasAnySubPermissionOf(userId, permissions); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { return inner.groupHasAnySubPermissionOf(groupId, permission); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    { return inner.groupHasAnySubPermissionOf(groupId, permissions); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    { return inner.groupHasAnySubPermissionOf(groupId, permissions); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { return inner.isOrAnySubPermissionOfIsDefault(permission); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    { return inner.isOrAnySubPermissionOfIsDefault(permissions); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    { return inner.isOrAnySubPermissionOfIsDefault(permissions); }

    @Override
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { return inner.hasAnySubPermissionOf(permGroup, permission, deferToDefault); }

    @Override
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, String[] permissions, boolean deferToDefault)
    { return inner.hasAnySubPermissionOf(permGroup, permissions, deferToDefault); }

    @Override
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    { return inner.hasAnySubPermissionOf(permGroup, permissions, deferToDefault); }

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
    protected String getPermissionArg(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { return inner.getPermissionArg(permGroup, permission, deferToDefault); }

    @Override
    public boolean userHasGroup(ID userId, String groupName)
    { return inner.userHasGroup(userId, groupName); }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    { return inner.groupExtendsFromGroup(groupId, superGroupName); }

    @Override
    public boolean isDefaultGroup(String groupId)
    { return inner.isDefaultGroup(groupId); }

    @Override
    protected boolean hasGroup(PermissionGroup permGroup, String groupId, boolean deferToDefault)
    { return inner.hasGroup(permGroup, groupId, deferToDefault); }

    @Override
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    { return inner.userHasAllGroups(userId, groupNames); }

    @Override
    public boolean userHasAllGroups(ID userId, String... groupNames)
    { return inner.userHasAllGroups(userId, groupNames); }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    { return inner.groupExtendsFromAllGroups(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    { return inner.groupExtendsFromAllGroups(groupName, superGroupNames); }

    @Override
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    { return inner.areAllDefaultGroups(groupNames); }

    @Override
    public boolean areAllDefaultGroups(String... groupNames)
    { return inner.areAllDefaultGroups(groupNames); }

    @Override
    protected boolean hasAllGroups(PermissionGroup permGroup, Iterable<String> groupNames, boolean deferToDefault)
    { return inner.hasAllGroups(permGroup, groupNames, deferToDefault); }

    @Override
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    { return inner.userHasAnyGroups(userId, groupNames); }

    @Override
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    { return inner.userHasAnyGroups(userId, groupNames); }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    { return inner.groupExtendsFromAnyGroups(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    { return inner.groupExtendsFromAnyGroups(groupName, superGroupNames); }

    @Override
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    { return inner.anyAreDefaultGroups(groupNames); }

    @Override
    public boolean anyAreDefaultGroups(String... groupNames)
    { return inner.anyAreDefaultGroups(groupNames); }

    @Override
    protected boolean hasAnyGroups(PermissionGroup permGroup, Iterable<String> groupNames, boolean deferToDefault)
    { return inner.hasAnyGroups(permGroup, groupNames, deferToDefault); }

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
    public Path getUsersFilePath()
    { return inner.getUsersFilePath(); }

    @Override
    public Path getGroupsFilePath()
    { return inner.getGroupsFilePath(); }

    @Override
    public Function<ID, String> getIdToStringFunction()
    { return inner.getIdToStringFunction(); }

    @Override
    public Function<String, ID> getIdFromStringFunction()
    { return inner.getIdFromStringFunction(); }

    @Override
    public Double getGroupPriority(String groupName)
    { return inner.getGroupPriority(groupName); }

    @Override
    public Long getGroupPriorityAsLong(String groupName)
    { return inner.getGroupPriorityAsLong(groupName); }

    @Override
    public PermissionGroup.Priority getGroupPriorityAsObject(String groupName)
    { return inner.getGroupPriorityAsObject(groupName); }

    @Override
    public List<String> getUserPermissions(ID userId)
    { return inner.getUserPermissions(userId); }

    @Override
    public List<String> getGroupPermissions(String groupName)
    { return inner.getGroupPermissions(groupName); }

    @Override
    public List<String> getDefaultPermissions()
    { return inner.getDefaultPermissions(); }

    @Override
    protected List<String> getPermissions(PermissionGroup permGroup)
    { return inner.getPermissions(permGroup); }

    @Override
    public List<String> getUserPermissionsWithArgs(ID userId)
    { return inner.getUserPermissionsWithArgs(userId); }

    @Override
    public List<String> getGroupPermissionsWithArgs(String groupName)
    { return inner.getGroupPermissionsWithArgs(groupName); }

    @Override
    public List<String> getDefaultPermissionsWithArgs()
    { return inner.getDefaultPermissionsWithArgs(); }

    @Override
    protected List<String> getPermissionsWithArgs(PermissionGroup permGroup)
    { return inner.getPermissionsWithArgs(permGroup); }

    @Override
    public Collection<PermissionStatus> getAllUserPermissionStatuses(ID userId)
    { return inner.getAllUserPermissionStatuses(userId); }

    @Override
    public Collection<PermissionStatus> getAllGroupPermissionStatuses(String groupName)
    { return inner.getAllGroupPermissionStatuses(groupName); }

    @Override
    public Collection<PermissionStatus> getAllDefaultPermissionStatuses()
    { return inner.getAllDefaultPermissionStatuses(); }

    @Override
    protected Collection<PermissionStatus> getAllPermissionsStatuses(PermissionGroup permGroup)
    { return inner.getAllPermissionsStatuses(permGroup); }

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
    protected List<String> getGroupsOf(PermissionGroup permGroup)
    { return inner.getGroupsOf(permGroup); }

    @Override
    PermissionGroup getGroupPermissionsGroup(String groupName)
    { return inner.getGroupPermissionsGroup(groupName); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName)
    { return inner.getGroupPermissionsGroupOrNew(groupName); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, long priority)
    { return inner.getGroupPermissionsGroupOrNew(groupName, priority); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, double priority)
    { return inner.getGroupPermissionsGroupOrNew(groupName, priority); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, PermissionGroup.Priority priority)
    { return inner.getGroupPermissionsGroupOrNew(groupName, priority); }

    @Override
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, String priorityAsString) throws InvalidPriorityException
    { return inner.getGroupPermissionsGroupOrNew(groupName, priorityAsString); }

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
    public void absorb(PermissionsRegistry<ID> other)
    { inner.absorb(other); }

    @Override
    public Permission assignUserPermission(ID userId, String permission)
    { return inner.assignUserPermission(userId, permission); }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    { return inner.assignGroupPermission(groupId, permission); }

    @Override
    public Permission assignDefaultPermission(String permission)
    { return inner.assignDefaultPermission(permission); }

    @Override
    protected Permission assignPermission(PermissionGroup permGroup, String permission)
    { return inner.assignPermission(permGroup, permission); }

    @Override
    public void assignUserPermissions(ID userId, List<String> permissions)
    { inner.assignUserPermissions(userId, permissions); }

    @Override
    public void assignUserPermissions(ID userId, String[] permissions)
    { inner.assignUserPermissions(userId, permissions); }

    @Override
    public void assignGroupPermissions(String groupName, List<String> permissions)
    { inner.assignGroupPermissions(groupName, permissions); }

    @Override
    public void assignGroupPermissions(String groupName, String[] permissions)
    { inner.assignGroupPermissions(groupName, permissions); }

    @Override
    public void assignDefaultPermissions(List<String> permissions)
    { inner.assignDefaultPermissions(permissions); }

    @Override
    public void assignDefaultPermissions(String[] permissions)
    { inner.assignDefaultPermissions(permissions); }

    @Override
    protected void assignPermissions(PermissionGroup permGroup, List<String> permissions)
    { inner.assignPermissions(permGroup, permissions); }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    { return inner.revokeUserPermission(userId, permission); }

    @Override
    public Permission revokeGroupPermission(String groupId, String permission)
    { return inner.revokeGroupPermission(groupId, permission); }

    @Override
    public Permission revokeDefaultPermission(String permission)
    { return inner.revokeDefaultPermission(permission); }

    @Override
    protected Permission revokePermission(PermissionGroup permGroup, String permission)
    { return inner.revokePermission(permGroup, permission); }

    @Override
    public void assignGroupToUser(ID userId, String groupNameBeingAssigned)
    { inner.assignGroupToUser(userId, groupNameBeingAssigned); }

    @Override
    public void assignGroupToGroup(String groupName, String groupNameBeingAssigned)
    { inner.assignGroupToGroup(groupName, groupNameBeingAssigned); }

    @Override
    public void assignDefaultGroup(String groupNameBeingAssigned)
    { inner.assignDefaultGroup(groupNameBeingAssigned); }

    @Override
    protected void assignGroupTo(PermissionGroup permGroup, String groupNameBeingAssigned, boolean checkForCircular)
    { inner.assignGroupTo(permGroup, groupNameBeingAssigned, checkForCircular); }

    @Override
    public void assignGroupsToUser(ID userId, List<String> groupNamesBeingAssigned)
    { inner.assignGroupsToUser(userId, groupNamesBeingAssigned); }

    @Override
    public void assignGroupsToUser(ID userId, String[] groupNamesBeingAssigned)
    { inner.assignGroupsToUser(userId, groupNamesBeingAssigned); }

    @Override
    public void assignGroupsToGroup(String groupName, List<String> groupNamesBeingAssigned)
    { inner.assignGroupsToGroup(groupName, groupNamesBeingAssigned); }

    @Override
    public void assignGroupsToGroup(String groupName, String[] groupNamesBeingAssigned)
    { inner.assignGroupsToGroup(groupName, groupNamesBeingAssigned); }

    @Override
    public void assignDefaultGroups(List<String> groupNameBeingAssigned)
    { inner.assignDefaultGroups(groupNameBeingAssigned); }

    @Override
    public void assignDefaultGroups(String[] groupNameBeingAssigned)
    { inner.assignDefaultGroups(groupNameBeingAssigned); }

    @Override
    protected void assignGroupsTo(PermissionGroup permGroup, List<String> groupNamesBeingAssigned, boolean checkForCircular)
    { inner.assignGroupsTo(permGroup, groupNamesBeingAssigned, checkForCircular); }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupNameBeingRevoked)
    { return inner.revokeGroupFromUser(userId, groupNameBeingRevoked); }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupNameBeingRevoked)
    { return inner.revokeGroupFromGroup(groupId, groupNameBeingRevoked); }

    @Override
    public boolean revokeDefaultGroup(String groupNameBeingRevoked)
    { return inner.revokeDefaultGroup(groupNameBeingRevoked); }

    @Override
    protected boolean revokeGroupFrom(PermissionGroup permGroup, String groupNameBeingRevoked)
    { return inner.revokeGroupFrom(permGroup, groupNameBeingRevoked); }

    @Override
    public void clear()
    { inner.clear(); }

    @Override
    protected void markAsModified()
    { inner.markAsModified(); }

    @Override
    protected void saveUsers(BufferedWriter writer) throws IOException
    { inner.saveUsers(writer); }

    @Override
    protected void saveGroups(BufferedWriter writer) throws IOException
    { inner.saveGroups(writer); }

    @Override
    protected void saveUsers() throws IOException
    { inner.saveUsers(); }

    @Override
    protected void saveGroups() throws IOException
    { inner.saveGroups(); }

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
    protected void loadUsers() throws IOException
    { inner.loadUsers(); }

    @Override
    protected void loadGroups() throws IOException
    { inner.loadGroups(); }

    @Override
    protected void loadUsersFromSaveString(String saveString) throws IOException
    { inner.loadUsersFromSaveString(saveString); }

    @Override
    protected void loadGroupsFromSaveString(String saveString) throws IOException
    { inner.loadGroupsFromSaveString(saveString); }

    @Override
    public void load() throws IOException
    { inner.load(); }

    @Override
    public int hashCode()
    { return inner.hashCode(); }

    @SuppressWarnings("EqualsWhichDoesntCheckParameterClass")
    @Override
    public boolean equals(Object obj)
    { return inner.equals(obj); }

    @Override
    public String toString()
    { return inner.toString(); }
    //endregion
}
