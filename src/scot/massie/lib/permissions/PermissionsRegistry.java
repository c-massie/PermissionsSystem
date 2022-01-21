package scot.massie.lib.permissions;

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
 * <p>A registry for assigning permissions to users in a system and checking them.</p>
 *
 * <p>Users may be assigned permissions to indicate allowance to do something, or to provide some level of per-user
 * configurability.</p>
 *
 * <p>Permissions are provided as dot-separated alphanumeric strings. (e.g. "first.second.third") A permission is said
 * to "cover" another permission where the other permission starts with the dot-separated sections ("nodes") of the
 * first, in order. (e.g. "first.second.third" covers "first.second.third.fourth", but not "first.second.fourth" or
 * "second.first.third.fourth") A permission does not cover another where the other starts with the first, but doesn't
 * have the first's last node exactly. (e.g. "first.second.thi" does not cover "first.second.third" or
 * "first.second.third.fourth")</p>
 *
 * <p>The "most relevant permission" a user has to a given permission is the permission the user has that covers the
 * given permission with the most number of nodes.</p>
 *
 * <p>Users may be assigned "Groups", which are referred to by name, as strings. Groups may have their own permissions
 * and may be assigned other groups. Groups may also have "priorities" (numbers) associated with them. Where a user or
 * group does not have a given permission, it then checks the groups it is assigned, in order of priority from highest
 * to lowest, to see if they cover the given permission.</p>
 *
 * <p>A default "*" group may be defined with permissions and/or groups, which all users are considered to have assigned
 * to them. This may be thought of as a lowest priority group associated with all users.</p>
 *
 * <p>Permissions may be prefixed with a "-" to indicate that a user does *not* have the given permission, that that
 * permission is negated. If the most relevant permission to a given permission a user or group has is negating, that
 * user or group is considered not to have the given permission.</p>
 *
 * <p>Permissions may be suffixed with a ".*" to indicate that they cover permissions longer than it, but not the
 * permission itself. ("first.second.*" covers "first.second.third", but not "first.second")</p>
 *
 * <p>Permissions may be followed by (after any suffixes) a colon (":") and any arbitrary string. This string is the
 * "permission argument". When getting the permission argument of a given permission, it returns the argument of the
 * most relevant permission. Permission arguments may be multiple lines.</p>
 * @param <ID> The type of the unique identifier used to represent users.
 */
public interface PermissionsRegistry<ID extends Comparable<? super ID>>
{
    //region Assertions
    //region Permissions
    //region Has
    /**
     * Asserts that a specified user "has" a given permission.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to assert has the given permission.
     * @param permission The permission to assert that the user has.
     * @throws UserMissingPermissionException If the user does not have the given permission.
     */
    void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException;

    /**
     * Asserts that a specified group "has" a given permission.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to assert has the given permission
     * @param permission The permission to assert that the group has.
     * @throws GroupMissingPermissionException If the group does not have the given permission.
     */
    void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException;

    /**
     * Asserts that a given permission is part of the default permissions.
     * @param permission The permission to assert is default.
     * @throws PermissionNotDefaultException If the default permissions does not include the given permission.
     */
    void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException;
    //endregion

    //region Has all
    /**
     * Asserts that the specified user "has" all of the given permissions.
     * @see #userHasAllPermissions(Comparable, Iterable)
     * @param userId The ID of the user to assert has all of the given permissions
     * @param permissions The permissions to assert that the user has.
     * @throws UserMissingPermissionException If the user is missing any of the given permissions.
     */
    void assertUserHasAllPermissions(ID userId, Iterable<String> permissions)
            throws UserMissingPermissionException;

    /**
     * Asserts that the specified user "has" all of the given permissions.
     * @see #userHasAllPermissions(Comparable, String...)
     * @param userId The ID of the user to assert has all of the given permissions
     * @param permissions The permissions to assert that the user has.
     * @throws UserMissingPermissionException If the user is missing any of the given permissions.
     */
    void assertUserHasAllPermissions(ID userId, String... permissions)
            throws UserMissingPermissionException;

    /**
     * Asserts that the specified group "has" all of the given permissions.
     * @see #groupHasAllPermissions(String, Iterable)
     * @param groupName The name of the group to assert has all of the given permissions
     * @param permissions The permissions to assert that the group has.
     * @throws GroupMissingPermissionException If the group is missing any of the given permissions.
     */
    void assertGroupHasAllPermissions(String groupName, Iterable<String> permissions)
            throws GroupMissingPermissionException;

    /**
     * Asserts that the specified group "has" all of the given permissions.
     * @see #groupHasAllPermissions(String, String...)
     * @param groupName The name of the group to assert has all of the given permissions
     * @param permissions The permissions to assert that the group has.
     * @throws GroupMissingPermissionException If the group is missing any of the given permissions.
     */
    void assertGroupHasAllPermissions(String groupName, String... permissions)
            throws GroupMissingPermissionException;

    /**
     * Asserts that all of the given permissions are default.
     * @see #areAllDefaultPermissions(Iterable)
     * @param permissions The permissions to assert are all default.
     * @throws PermissionNotDefaultException If the default permissions does not cover any of the given permissions.
     */
    void assertAllAreDefaultPermissions(Iterable<String> permissions)
            throws PermissionNotDefaultException;

    /**
     * Asserts that all of the given permissions are default.
     * @see #areAllDefaultPermissions(String...)
     * @param permissions The permissions to assert are all default.
     * @throws PermissionNotDefaultException If the default permissions does not cover any of the given permissions.
     */
    void assertAllAreDefaultPermissions(String... permissions)
            throws PermissionNotDefaultException;
    //endregion

    //region Has any
    /**
     * Asserts that the specified user "has" any of the given permissions.
     * @see #userHasAnyPermissions(Comparable, Iterable)
     * @param userId The ID of the user to assert has any of the given permissions
     * @param permissions The permissions to assert that the user has any of.
     * @throws UserMissingPermissionException If the user has none of the given permissions.
     */
    void assertUserHasAnyPermission(ID userId, Iterable<String> permissions)
            throws UserMissingPermissionException;

    /**
     * Asserts that the specified user "has" any of the given permissions.
     * @see #userHasAnyPermissions(Comparable, String...)
     * @param userId The ID of the user to assert has any of the given permissions
     * @param permissions The permissions to assert that the user has any of.
     * @throws UserMissingPermissionException If the user has none of the given permissions.
     */
    void assertUserHasAnyPermission(ID userId, String... permissions)
            throws UserMissingPermissionException;

    /**
     * Asserts that the specified group "has" any of the given permissions.
     * @see #groupHasAnyPermissions(String, Iterable)
     * @param groupName The name of the group to assert has any of the given permissions
     * @param permissions The permissions to assert that the group has any of.
     * @throws GroupMissingPermissionException If the group has none of the given permissions.
     */
    void assertGroupHasAnyPermission(String groupName, Iterable<String> permissions)
            throws GroupMissingPermissionException;

    /**
     * Asserts that the specified group "has" any of the given permissions.
     * @see #groupHasAnyPermissions(String, String...)
     * @param groupName The name of the group to assert has any of the given permissions
     * @param permissions The permissions to assert that the group has any of.
     * @throws GroupMissingPermissionException If the group has none of the given permissions.
     */
    void assertGroupHasAnyPermission(String groupName, String... permissions)
            throws GroupMissingPermissionException;

    /**
     * Asserts that any of the given permissions are default.
     * @see #anyAreDefaultPermissions(Iterable)
     * @param permissions The permissions to assert are default.
     * @throws PermissionNotDefaultException If none of the given permissions are default.
     */
    void assertAnyAreDefaultPermission(Iterable<String> permissions)
            throws PermissionNotDefaultException;

    /**
     * Asserts that any of the given permissions are default.
     * @see #anyAreDefaultPermissions(String...)
     * @param permissions The permissions to assert are default.
     * @throws PermissionNotDefaultException If none of the given permissions are default.
     */
    void assertAnyAreDefaultPermission(String... permissions)
            throws PermissionNotDefaultException;
    //endregion
    //endregion
    //endregion

    //region Accessors
    //region Permission queries
    //region Get status
    //region Single
    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and the given
     * permission.
     * @param userId The ID of the user to get the status information of the given permission.
     * @param permission The permission to get the status of relating to the specified user.
     * @return A PermissionStatus object containing the permission queried, whether or not the user "has" it, and the
     *         permission argument if applicable.
     */
    PermissionStatus getUserPermissionStatus(ID userId, String permission);

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and the given
     * permission.
     * @param groupName The name of the group to get the status information of the given permission.
     * @param permission The permission to get the status of relating to the specified group.
     * @return A PermissionStatus object containing the permission queried, whether or not the group "has" it, and the
     *         permission argument if applicable.
     */
    PermissionStatus getGroupPermissionStatus(String groupName, String permission);

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and the
     * given permission.
     * @param permission The permission to get the status of relating to the default permissions.
     * @return A permissionStatus object containing the permission queried, whether or not the permission is included
     *         in the default permissions, and the permission argument if applicable.
     */
    PermissionStatus getDefaultPermissionStatus(String permission);
    //endregion

    //region Multiple
    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and each of the
     * given permissions.
     * @param userId The ID of the user to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified user.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the user "has" it, and the permission argument if applicable.
     */
    Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions);

    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and each of the
     * given permissions.
     * @param userId The ID of the user to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified user.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the user "has" it, and the permission argument if applicable.
     */
    Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions);

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and each of the
     * given permissions.
     * @param groupName The name of the group to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified group.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the group "has" it, and the permission argument if applicable.
     */
    Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions);

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and each of the
     * given permissions.
     * @param groupName The name of the group to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified group.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the group "has" it, and the permission argument if applicable.
     */
    Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions);

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and each of
     * the given permissions.
     * @param permissions The permissions to get the status of relating to the default permissions.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the default permissions "has" it, and the permission argument if
     *         applicable.
     */
    Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions);

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and each of
     * the given permissions.
     * @param permissions The permissions to get the status of relating to the default permissions.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the default permissions "has" it, and the permission argument if
     *         applicable.
     */
    Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions);
    //endregion
    //endregion

    //region Has
    /**
     * <p>Checks whether or not a specified user "has" a given permission.</p>
     *
     * <p>That is, checks whether the given user's permissions contains (directly, via a group it's assigned, or via the
     * default permissions) at least one permission that covers the given permission, and whether the most relevant
     * permission of the given user to the given permission is an allowing permission. (as opposed to a negating
     * permission.)</p>
     * @param userId The ID of the user to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the user has the given permission as defined above. Otherwise, false.
     */
    boolean userHasPermission(ID userId, String permission);

    /**
     * <p>Checks whether or not a specified group "has" a given permission.</p>
     *
     * <p>That is, checks whether the given group's permissions contains (directly or via a group it extends from, but
     * not via the default permissions) at least one permission that covers the given permission, and whether the most
     * relevant permission of the given group to the given permission is an allowing permission. (as opposed to a
     * negating permission.)</p>
     * @param groupName The name of the group to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the group has the given permission as defined above. Otherwise, false.
     */
    boolean groupHasPermission(String groupName, String permission);

    /**
     * <p>Checks whether or not the default permissions "has" a given permission.</p>
     *
     * <p>That is, checks whether the default permissions contains (directly or via a group assigned as a default group)
     * at least one permission that covers the given permission, and whether the most relevant permission of the default
     * permissions is an allowing permission. (as opposed to a negating permission.)</p>
     * @param permission The permission to check for.
     * @return True if the default permissions has the given permission as defined above. Otherwise, false.
     */
    boolean isDefaultPermission(String permission);
    //endregion

    //region Has all
    /**
     * Checks whether or not a specified user has all of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has all of the given permissions. Otherwise, false.
     */
    boolean userHasAllPermissions(ID userId, Iterable<String> permissions);

    /**
     * Checks whether or not a specified user has all of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has all of the given permissions. Otherwise, false.
     */
    boolean userHasAllPermissions(ID userId, String... permissions);

    /**
     * Checks whether or not a specified group has all of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has all of the given permissions. Otherwise, false.
     */
    boolean groupHasAllPermissions(String groupName, Iterable<String> permissions);

    /**
     * Checks whether or not a specified group has all of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has all of the given permissions. Otherwise, false.
     */
    boolean groupHasAllPermissions(String groupName, String... permissions);

    /**
     * Checks whether or not all given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if all of the given permissions are default. Otherwise, false.
     */
    boolean areAllDefaultPermissions(Iterable<String> permissions);

    /**
     * Checks whether or not all given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if all of the given permissions are default. Otherwise, false.
     */
    boolean areAllDefaultPermissions(String... permissions);
    //endregion

    //region Has any
    /**
     * Checks whether or not a specified user has any of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions. Otherwise, false.
     */
    boolean userHasAnyPermissions(ID userId, Iterable<String> permissions);

    /**
     * Checks whether or not a specified user has any of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions. Otherwise, false.
     */
    boolean userHasAnyPermissions(ID userId, String... permissions);

    /**
     * Checks whether or not a specified group has any of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions. Otherwise, false.
     */
    boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions);

    /**
     * Checks whether or not a specified group has any of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions. Otherwise, false.
     */
    boolean groupHasAnyPermissions(String groupName, String... permissions);

    /**
     * Checks whether or not any of the given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if any of the given permissions are default. Otherwise, false.
     */
    boolean anyAreDefaultPermissions(Iterable<String> permissions);

    /**
     * Checks whether or not any of the given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if any of the given permissions are default. Otherwise, false.
     */
    boolean anyAreDefaultPermissions(String... permissions);
    //endregion

    //region Has any subpermission of
    /**
     * Checks whether or not a specified user "has" a given permission or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the user has the given permission or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    boolean userHasAnySubPermissionOf(ID userId, String permission);

    /**
     * Checks whether or not a specified user "has" any of the given permissions or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions);

    /**
     * Checks whether or not a specified user "has" any of the given permissions or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    boolean userHasAnySubPermissionOf(ID userId, String... permissions);

    /**
     * Checks whether or not a specified group "has" a given permission or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the group has the given permission or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    boolean groupHasAnySubPermissionOf(String groupId, String permission);

    /**
     * Checks whether or not a specified group "has" any of the given permissions or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions);

    /**
     * Checks whether or not a specified group "has" any of the given permissions or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    boolean groupHasAnySubPermissionOf(String groupId, String... permissions);

    /**
     * Checks whether or not the default permissions "has" a given permission or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permission The permission to check for.
     * @return True if the default permissions has the given permission or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    boolean isOrAnySubPermissionOfIsDefault(String permission);

    /**
     * Checks whether or not the default permissions "has" any of the given permissions or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if the default permissions has any of the given permissions or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions);

    /**
     * Checks whether or not the default permissions "has" any of the given permissions or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if the default permissions has any of the given permissions or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    boolean isOrAnySubPermissionOfIsDefault(String... permissions);
    //endregion

    //region Args
    /**
     * <p>Gets the argument associated with the given permission for the given user.</p>
     *
     * <p>That is, where a given user has a permission as described in {@link #userHasPermission(Comparable, String)}
     * and where the most relevant permission a user has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param userId The user to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the user has the given permission and the most relevant permission the user has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    String getUserPermissionArg(ID userId, String permission);

    /**
     * <p>Gets the argument associated with the given permission for the given group.</p>
     *
     * <p>That is, where a given group has a permission as described in {@link #groupHasPermission(String, String)} and
     * where the most relevant permission a group has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param groupId The name of the group to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the group has the given permission and the most relevant permission the group has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    String getGroupPermissionArg(String groupId, String permission);

    /**
     * <p>Gets the argument associated with the given permission in the default permissions.</p>
     *
     * <p>That is, where the default permissions has a permission as described in {@link #isDefaultPermission(String)}
     * and where the most relevant default permission to the given permissions has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param permission The permission to get the permission argument of.
     * @return If the default permissions has the given permission and the most relevant default permission to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    String getDefaultPermissionArg(String permission);
    //endregion
    //endregion

    //region Group queries
    //region Has
    /**
     * Gets whether or not the specified user is assigned a group with the given name. (directly, via an assigned group,
     * or via the default permissions.)
     * @param userId The ID of the user to check whether or not they have the specified group.
     * @param groupName The name of the group to check whether or not the user has.
     * @return True if the user, any group assigned to the user, or the default permissions, has a group by the given
     *         name. Otherwise, false.
     */
    boolean userHasGroup(ID userId, String groupName);

    /**
     * Gets whether or not one group with the specified name is assigned another, by the other specified name.
     * (directly or via another assigned group, but not via the default permissions.)
     * @param groupId The name of the group to check whether it extends from the other group specified.
     * @param superGroupName The name of the group to check whether the other group specifies it.
     * @return True if the group or any group assigned to the group (that is, that the group is extended from), has a
     *         group assigned to it by the given name. Otherwise, false.
     */
    boolean groupExtendsFromGroup(String groupId, String superGroupName);

    /**
     * Gets whether or not the group with the specified name is extended from by the default permissions, is assigned
     * as a default group. (directly or via another group assigned as a default group)
     * @param groupId The name of the group to check whether or not is a default group.
     * @return True if the default permissions or any group assigned to the default permissions (assigned as a default
     *         group) is assigned a group by the given name.
     */
    boolean isDefaultGroup(String groupId);
    //endregion

    //region Has all
    /**
     * Gets whether or not the specified user is assigned groups with all of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by all of the given names. Otherwise, false.
     */
    boolean userHasAllGroups(ID userId, Iterable<String> groupNames);

    /**
     * Gets whether or not the specified user is assigned groups with all of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by all of the given names. Otherwise, false.
     */
    boolean userHasAllGroups(ID userId, String... groupNames);

    /**
     * Gets whether or not the specified group extends from all of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from all of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                      extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by all of the given names. Otherwise, false.
     */
    boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames);

    /**
     * Gets whether or not the specified group extends from all of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from all of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                      extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by all of the given names. Otherwise, false.
     */
    boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames);

    /**
     * Gets whether or not all of the specified groups are default. That is, whether or not they're all included in the
     * default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by all of the given names. Otherwise, false.
     */
    boolean areAllDefaultGroups(Iterable<String> groupNames);

    /**
     * Gets whether or not all of the specified groups are default. That is, whether or not they're all included in the
     * default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by all of the given names. Otherwise, false.
     */
    boolean areAllDefaultGroups(String... groupNames);
    //endregion

    //region Has any
    /**
     * Gets whether or not the specified user is assigned groups with any of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by any of the given names. Otherwise, false.
     */
    boolean userHasAnyGroups(ID userId, Iterable<String> groupNames);

    /**
     * Gets whether or not the specified user is assigned groups with any of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by any of the given names. Otherwise, false.
     */
    boolean userHasAnyGroups(ID userId, String... groupNames);

    /**
     * Gets whether or not the specified group extends from any of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from any of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                        extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by any of the given names. Otherwise, false.
     */
    boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames);

    /**
     * Gets whether or not the specified group extends from any of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from any of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                        extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by any of the given names. Otherwise, false.
     */
    boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames);

    /**
     * Gets whether or not any of the specified groups are default. That is, whether or not any of them are included in
     * the default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by any of the given names. Otherwise, false.
     */
    boolean anyAreDefaultGroups(Iterable<String> groupNames);

    /**
     * Gets whether or not any of the specified groups are default. That is, whether or not any of them are included in
     * the default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by any of the given names. Otherwise, false.
     */
    boolean anyAreDefaultGroups(String... groupNames);
    //endregion
    //endregion

    //region State
    /**
     * Gets whether or not the permissions registry has had its values modified since the last time it was saved or
     * loaded.
     * @return True if the permissions registry has been modified since being saved or loaded. Otherwise, false.
     */
    boolean hasBeenDifferentiatedFromFiles();
    //endregion

    //region Getters
    //region Members
    /**
     * Gets the names of all groups registered with the permissions registry. This includes groups that don't have any
     * given permissions and aren't assigned to any users or other groups.
     * @return A collection containing the names of all groups registered with the permissions registry.
     */
    Collection<String> getGroupNames();

    /**
     * Gets all users registered with the permissions registry. This includes users that don't have any given
     * permissions.
     * @return A collection containing the IDs of all users registered with the permissions registry.
     */
    Collection<ID> getUsers();

    /**
     * Gets the path of this registry's users file.
     * @return The path of this registry's users file, or null if this registry has no users file.
     */
    Path getUsersFilePath();

    /**
     * Gets the path of this registry's groups file.
     * @return The path of this registry's groups file, or null if this registry has no groups file.
     */
    Path getGroupsFilePath();

    /**
     * Gets the function responsible for creating string representations of user IDs.
     * @return The function used for converting user IDs into strings.
     */
    Function<ID, String> getIdToStringFunction();

    /**
     * Gets the function responsible for parsing user IDs from their string representations.
     * @return The function used for converting string representations of user IDs into user IDs.
     */
    Function<String, ID> getIdFromStringFunction();
    //endregion

    //region Group priorities
    /**
     * Gets the priority of the group with a given name. (As a double)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a boxed double, or null if
     *         no such group exists.
     */
    Double getGroupPriority(String groupName);

    /**
     * Gets the priority of the group with a given name. (As a long)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a boxed long, or null if no
     *         such group exists.
     */
    Long getGroupPriorityAsLong(String groupName);

    /**
     * Gets the priority of the group with a given name. (As an object containing long and double representations.)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a wrapper object containing
     *         the double and long representations of it and an indication of which it would best be represented as, or
     *         null if no such group exists.
     */
    PermissionGroup.Priority getGroupPriorityAsObject(String groupName);
    //endregion

    //region Permissions
    /**
     * <p>Gets a list of the permissions directly assigned to the specified user.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     *
     * <p>The string representations of the permissions of the user returned do not include permission arguments.</p>
     * @param userId The ID of the user to get the permissions of.
     * @return A sorted list of all permissions of the specified user, not including referenced groups or the default
     *         permissions, and not including permission arguments.
     */
    List<String> getUserPermissions(ID userId);

    /**
     * <p>Gets a list of the permissions directly assigned to the specified group.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     *
     * <p>The string representations of the permissions of the group returned do not include permission arguments.</p>
     * @param groupName The name of the group to get the permissions of.
     * @return A sorted list of all the permissions of the specified group, not including referenced groups or the
     *         default permissions, and not including permission arguments.
     */
    List<String> getGroupPermissions(String groupName);

    /**
     * <p>Gets a list of the default permissions.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include default
     * groups.</p>
     *
     * <p>The string representations of the default permissions returned do not include permission arguments.</p>
     * @return A sorted list of all the default permissions, not including default groups, and not including permission
     *         arguments.
     */
    List<String> getDefaultPermissions();

    /**
     * <p>Gets a list of the permissions directly assigned to the specified user, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     * @param userId The ID of the user to get the permissions of.
     * @return A sorted list of all permissions of the specified user, not including referenced groups or the default
     *         permissions, and including permission arguments if applicable.
     */
    List<String> getUserPermissionsWithArgs(ID userId);

    /**
     * <p>Gets a list of the permissions directly assigned to the specified group, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     * @param groupName The name of the group to get the permissions of.
     * @return A sorted list of all the permissions of the specified group, not including referenced groups or the
     *         default permissions, and including permission arguments if applicable.
     */
    List<String> getGroupPermissionsWithArgs(String groupName);

    /**
     * <p>Gets a list of the default permissions, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include default
     * groups.</p>
     * @return A sorted list of all the default permissions, not including default groups, and including permission
     *         arguments if applicable.
     */
    List<String> getDefaultPermissionsWithArgs();
    //endregion

    //region All permission statuses
    /**
     * Gets all of a user's permissions and their statuses.
     * @param userId The ID of the user.
     * @return A collection of permission statuses for all permissions of the specified user, not including referenced
     *         groups or the default permissions.
     */
    Collection<PermissionStatus> getAllUserPermissionStatuses(ID userId);

    /**
     * Gets all of a group's permissions and their statuses.
     * @param groupName The name of the group.
     * @return A collection of permission statuses for all permissions of the specified group, not including referenced
     *         groups or the default permissions.
     */
    Collection<PermissionStatus> getAllGroupPermissionStatuses(String groupName);

    /**
     * Gets all of the default permissions and their statuses.
     * @return A collection of permission statuses for all default permissions, not including those of default groups.
     */
    Collection<PermissionStatus> getAllDefaultPermissionStatuses();
    //endregion

    //region Groups
    /**
     * Gets the names of all groups the specified user is assigned.
     * @param userId The ID of the user to get the groups of.
     * @return A list of the names of all groups the specified user is assigned, in order of group priorities from
     *         highest to lowest.
     */
    List<String> getGroupsOfUser(ID userId);

    /**
     * Gets the names of all groups the specified group is assigned.
     * @param groupId The name of the group to get the groups it's extended from.
     * @return A list of the names of all groups the specified group is assigned, in order of group priorities from
     *         highest to lowest.
     */
    List<String> getGroupsOfGroup(String groupId);

    /**
     * Gets the names of all default groups.
     * @return A list of the names of all default groups, in order of group priorities from highest to lowest.
     */
    List<String> getDefaultGroups();
    //endregion
    //endregion
    //endregion

    //region Mutators
    //region Other registries
    //region Absorb
    /**
     * Adds the users, groups, and default permissions from another permissions registry to this one.
     * @apiNote Where the groups from the other permissions registry already exist in this one, priority will not be
     *          overridden. But priority will be copied for groups that do not currently exist in this permissions
     *          registry.
     * @param other The permissions registry to absorb the information from.
     */
    void absorb(PermissionsRegistry<ID> other);
    //endregion

    //region Remove contents of

    // Is there a better name than "removeContentsOf"? Something like "Outsorb", but that isn't a word.

    /**
     * Removes the users, groups, and default permissions of another permissions registry from this one.
     * @param other The permissions registry to remove the information in this one about.
     */
    void removeContentsOf(PermissionsRegistry<ID> other);
    //endregion
    //endregion

    //region Permissions
    //region Assign
    //region Single
    /**
     * Assigns a permission to a user.
     * @param userId The ID of the user to assign a permission to.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     */
    Permission assignUserPermission(ID userId, String permission);

    /**
     * Assigns a permission to a group.
     * @param groupId The name of the group to assign a permission to.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If the group name was not a valid group name.
     */
    Permission assignGroupPermission(String groupId, String permission);

    /**
     * Assigns a default permission. All users will be considered to have this permission unless otherwise overridden.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     */
    Permission assignDefaultPermission(String permission);
    //endregion

    //region Multiple
    /**
     * Assigns permissions to a user.
     * @param userId The ID of the user to assign permissions to.
     * @param permissions A list of permissions to assign.
     */
    void assignUserPermissions(ID userId, List<String> permissions);

    /**
     * Assigns permissions to a user.
     * @param userId The ID of the user to assign permissions to.
     * @param permissions An array of permissions to assign.
     */
    void assignUserPermissions(ID userId, String[] permissions);

    /**
     * Assigns permissions to a group.
     * @param groupName The name of the group to assign permissions to.
     * @param permissions A list of permissions to assign.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If the group name was not a valid group name.
     */
    void assignGroupPermissions(String groupName, List<String> permissions);

    /**
     * Assigns permissions to a group.
     * @param groupName The name of the group to assign permissions to.
     * @param permissions An array of permissions to assign.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If the group name was not a valid group name.
     */
    void assignGroupPermissions(String groupName, String[] permissions);

    /**
     * Assigns default permissions. All users will be considered to have these permissions unless otherwise overridden.
     * @param permissions An array of permissions to assign.
     */
    void assignDefaultPermissions(List<String> permissions);

    /**
     * Assigns default permissions. All users will be considered to have these permissions unless otherwise overridden.
     * @param permissions A list of permissions to assign.
     */
    void assignDefaultPermissions(String[] permissions);
    //endregion
    //endregion

    //region Revoke
    //region Single
    /**
     * Removes a permission from a user.
     * @param userId The ID of the user to remove a permission from.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    Permission revokeUserPermission(ID userId, String permission);

    /**
     * Removes a permission from a group.
     * @param groupeName The name of the group to remove a permission from.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    Permission revokeGroupPermission(String groupeName, String permission);

    /**
     * Removes a permission from the default permissions.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    Permission revokeDefaultPermission(String permission);
    //endregion

    //region All
    /**
     * Removes all direct permissions from a user.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     * @param userId The ID of the user to remove all permissions from.
     */
    void revokeAllUserPermissions(ID userId);

    /**
     * Removes all direct permissions from a group.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     * @param groupName The name of the group to remove all permissions from.
     */
    void revokeAllGroupPermissions(String groupName);

    /**
     * Removes all direct permissions from the default permissions.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     */
    void revokeAllDefaultPermissions();
    //endregion
    //endregion
    //endregion

    //region Groups
    //region Assign
    //region Single
    /**
     * Assigns a group to a user.
     * @param userId The ID of the user to assign a group to.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If the group name was not a valid group name.
     */
    void assignGroupToUser(ID userId, String groupNameBeingAssigned);

    /**
     * Assigns a group to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign another group to.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If either of the group names was not a valid group name.
     */
    void assignGroupToGroup(String groupName, String groupNameBeingAssigned);

    /**
     * Assigns a group to the default permissions.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If the group name was not a valid group name.
     */
    void assignDefaultGroup(String groupNameBeingAssigned);
    //endregion

    //region Multiple
    /**
     * Assigns groups to a user.
     * @param userId The ID of the user to assign groups to.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the group names were not valid group names.
     */
    void assignGroupsToUser(ID userId, List<String> groupNamesBeingAssigned);

    /**
     * Assigns groups to a user.
     * @param userId The ID of the user to assign groups to.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the group names were not valid group names.
     */
    void assignGroupsToUser(ID userId, String[] groupNamesBeingAssigned);

    /**
     * Assigns groups to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign other groups to.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the group names involved were not valid group names.
     */
    void assignGroupsToGroup(String groupName, List<String> groupNamesBeingAssigned);

    /**
     * Assigns groups to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign other groups to.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the group names involved were not valid group names.
     */
    void assignGroupsToGroup(String groupName, String[] groupNamesBeingAssigned);

    /**
     * Assigns groups to the default permissions.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the groups names were not valid group names.
     */
    void assignDefaultGroups(List<String> groupNamesBeingAssigned);

    /**
     * Assigns groups to the default permissions.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the groups names were not valid group names.
     */
    void assignDefaultGroups(String[] groupNamesBeingAssigned);
    //endregion
    //endregion

    //region Revoke
    //region Single
    /**
     * Deässigns a group from a user.
     * @param userId The ID of the user to deässign a group from.
     * @param groupNameBeingRevoked The name of the group being deässigned.
     * @return True if a group was deässigned from the user as a result of this call. Otherwise, false.
     */
    boolean revokeGroupFromUser(ID userId, String groupNameBeingRevoked);

    /**
     * Deässigns a group from another group.
     * @param groupName The name of the group to deässign another group from.
     * @param groupNameBeingRevoked The name of the group to deässign.
     * @return True if a group was deässigned from the group as a result of this call. Otherwise, false.
     */
    boolean revokeGroupFromGroup(String groupName, String groupNameBeingRevoked);

    /**
     * Deässigns a group as a default group.
     * @param groupNameBeingRevoked The group to deässign.
     * @return True if a group was deässigned as a default group as a result of this call. Otherwise, false.
     */
    boolean revokeDefaultGroup(String groupNameBeingRevoked);
    //endregion

    //region All

    /**
     * Removes all groups from a user.
     * @param userId The ID of the user to remove all groups from.
     */
    void revokeAllGroupsFromUser(ID userId);

    /**
     * Removes all groups from a group.
     * @param groupName The name of the groups to remove all groups from.
     */
    void revokeAllGroupsFromGroup(String groupName);

    /**
     * Removes all groups from the default permissions.
     */
    void revokeAllDefaultGroups();
    //endregion
    //endregion
    //endregion

    //region Clear
    /**
     * Removes all users, groups, and permissions from this registry.
     */
    void clear();

    /**
     * Removes all users from this registry.
     */
    void clearUsers();

    /**
     * Removes all information about the specified users from this registry.
     * @param userIds The IDs of the users to remove information about.
     */
    void clearUsers(Collection<ID> userIds);

    /**
     * Removes all information about the specified users from this registry.
     * @param userIds The IDs of the users to remove information about.
     */
    void clearUsers(ID[] userIds);

    /**
     * Removes all information about the specified user from this registry.
     * @param userId The ID of the user to remove information about.
     */
    void clearUser(ID userId);

    /**
     * Removes all groups from this registry. Users and the default permissions will no longer have any groups.
     */
    void clearGroups();

    /**
     * Removes the specified groups from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have any of the specified groups.
     * @param groupNames The names of the groups to remove.
     */
    void clearGroups(Collection<String> groupNames);

    /**
     * Removes the specified groups from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have any of the specified groups.
     * @param groupNames The names of the groups to remove.
     */
    void clearGroups(String[] groupNames);

    /**
     * Removes the specified group from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have the specified group.
     * @param groupName The name of the group to remove.
     */
    void clearGroup(String groupName);

    /**
     * Removes all default permissions and groups.
     */
    void clearDefaults();

    /**
     * Removes all groups from this registry that are currently unused by any users, other groups, or the default
     * permissions, and do not have any permissions or groups themselves. That is, groups that do not functionally
     * exist in this registry, but are left over from other operations.
     */
    void prune();

    /**
     * Removes the specified groups from this registry that are currently unused by any users, other groups, or the
     * default permissions, and do not have any permissions or groups themselves. That is, groups that do not
     * functionally exist in this registry, but are left over from other operations. Groups specified that *do* have any
     * permissions or other groups, or are had by any users, other groups, or the default permissions, are unaffected.
     * @param groupNames The names of the groups to remove if they match the aforementioned criteria.
     */
    void prune(Collection<String> groupNames);
    //endregion
    //endregion

    //region Saving & loading
    //region Saving
    /**
     * <p>Gets a reversible string representation of the permissions of all users in this registry.</p>
     *
     * <p>This provides the same text as would be written to the users file upon calling {@link #save()}.</p>
     * @return A reversible string representation of the permissions of all users in this registry.
     */
    String usersToSaveString();

    /**
     * <p>Gets a reversible string representation of the permissions of all groups in this registry.</p>
     *
     * <p>This provides the same text as would be written to the groups file upon calling {@link #save()}.</p>
     * @return A reversible string representation of the permissions of all groups in this registry.
     */
    String groupsToSaveString();

    /**
     * Saves the contents of this registry to the files specified.
     * @apiNote Does nothing if no users or groups files have been provided to the registry.
     * @throws IOException If an IO exception is thrown in the process of writing the save files.
     */
    void save() throws IOException;
    //endregion

    //region Loading
    /**
     * <p>Reads the provided save string, and adds read user records and permissions to the registry.</p>
     *
     * <p>The string provided should contain information in the same format as would be produced by
     * {@link #usersToSaveString()}.</p>
     *
     * <p>Does not clear registered users first.</p>
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the groups assigned to users have invalid names.
     */
    void loadUsersFromSaveString(String saveString) throws IOException;

    /**
     * <p>Reads the provided save string, and adds read group records and permissions to the registry.</p>
     *
     * <p>The string provided should contain information in the same format as would be produced by
     * {@link #groupsToSaveString()}.</p>
     *
     * <p>Does not clear registered groups first.</p>
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the groups loaded or any groups added to them have invalid names.
     */
    void loadGroupsFromSaveString(String saveString) throws IOException;

    /**
     * <p>Clears the registry and loads information from the users and groups files.</p>
     *
     * <p>Does nothing if the users and groups files have not been specified or cannot be read from.</p>
     * @throws IOException If an IO exception was thrown while reading from the users or groups files.
     * @throws GroupMapPermissionsRegistry.InvalidGroupNameException If any of the groups loaded or assigned to any group or user have invalid
     *                                   names.
     */
    void load() throws IOException;
    //endregion
    //endregion
}
