package scot.massie.lib.permissions;

import scot.massie.lib.events.Event;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.ProtectedEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.EventArgs;

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
    //region inner types

    /**
     * Specifier for what type of entry in the permissions registry is being targeted in a particular contents changed
     * event.
     */
    public enum PermissionsChangedTarget
    {
        /**
         * Events marked as affecting all entry types may affect (and likely do) the users, groups, and default
         * permissions of the registry.
         */
        ALL,

        /**
         * Events with this value affect individual users in the permissions registry.
         */
        USER,

        /**
         * Events with this value affect groups in the permissions registry. They will not affect users directly, but
         * may affect the users or groups they have indirectly by affecting the groups they have.
         */
        GROUP,

        /**
         * Events with this value affect the default permissions of the permissions registry. They will not affect users
         * or groups directly, but may affect the users or groups they have indirectly by affecting the default
         * permissions/groups which are fallen back on after checking the groups a particular user or group has.
         */
        DEFAULT_PERMISSIONS
    }

    //region EventArgs types
    /**
     * Event args for when the contents of the permissions registry change.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class ContentsChangedEventArgs<ID extends Comparable<? super ID>> implements EventArgs
    {
        /**
         * The registry this event belongs to. This event represents a change in the contents of this registry.
         */
        final PermissionsRegistryWithEvents<ID> registry;

        /**
         * What kind of entry of the registry is affected by this event.
         */
        final PermissionsChangedTarget target;

        /**
         * Where a user is targeted by this change, the user that was targeted. If a user was not targeted directly by
         * this change, this should always be null.
         */
        final ID userTargeted;

        /**
         * Where a group is targeted by this change, the group that was targeted. If a group was not targeted directly
         * by this change, this should always be null.
         */
        final String groupTargeted;

        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
         *                      directly targeted, this should always be null.
         */
        protected ContentsChangedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                           PermissionsChangedTarget target,
                                           ID userTargeted,
                                           String groupTargeted)
        {
            this.registry = registry;
            this.target = target;
            this.userTargeted = userTargeted;
            this.groupTargeted = groupTargeted;
        }

        /**
         * Gets the type of entry of the registry that was targeted in the action that raised this event.
         * @return The type of entry that was affected.
         */
        public PermissionsChangedTarget getTarget()
        { return target; }

        /**
         * Gets the ID of the user that was directly targeted by the action that raised this event.
         * @return Where a user was directly targeted, the ID of the user that was targeted. If a user was not
         *         *directly* targeted by the action that raised this event, null.
         */
        public ID getUserTargeted()
        { return userTargeted; }

        /**
         * Gets the ID of the group that was directly targeted by the action that raised this event.
         * @return Where a group was directly targeted, the ID of the group that was targeted. If a group was not
         *         *directly* targeted by the action that raised this event, null.
         */
        public String getGroupTargetedId()
        { return groupTargeted; }

        /**
         * Gets whether or not the user with the given ID was affected by the action that raised this event.
         * @param userId The ID of the user to check whether or not they were affected by this change.
         * @return True if the user, any group the user has, (directly or indirectly) the default permissions, or any
         *         group in the default permissions (directly or indirectly) was targeted by the change that raised this
         *         event. Otherwise, false, as any other change wouldn't affect the permissions the user with the given
         *         ID has, directly or indirectly.
         */
        public boolean userWasAffected(ID userId)
        {
            if(target == PermissionsChangedTarget.ALL || target == PermissionsChangedTarget.DEFAULT_PERMISSIONS)
                return true;

            if(target == PermissionsChangedTarget.USER)
                return userTargeted.equals(userId);

            // target == PermissionsChangedTarget.GROUP
            return registry.userHasGroup(userId, groupTargeted);
        }
    }

    /**
     * Event args for when a permission is assigned or revoked.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class PermissionEventArgs<ID extends Comparable<? super ID>>
            extends ContentsChangedEventArgs<ID>
    {
        /**
         * The permission that was associated with the action that raised this event.
         */
        final String permission;

        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
         *                      directly targeted, this should always be null.
         * @param permission The permission that was assigned or revoked in the action that raised this event.
         */
        protected PermissionEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                      PermissionsChangedTarget target,
                                      ID userTargeted,
                                      String groupTargeted,
                                      String permission)
        {
            super(registry, target, userTargeted, groupTargeted);
            this.permission = permission;
        }


        /**
         * Gets the permission that was involved in this change.
         * @return The permission that was involved in the action that raised the event.
         */
        public String getPermission()
        { return permission; }
    }

    /**
     * Event args for when a permission is assigned.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class PermissionAssignedEventArgs<ID extends Comparable<? super ID>>
            extends PermissionEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
         *                      directly targeted, this should always be null.
         * @param permission The permission that was assigned in the action that raised this event.
         */
        protected PermissionAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                              PermissionsChangedTarget target,
                                              ID userTargeted,
                                              String groupTargeted,
                                              String permission)
        { super(registry, target, userTargeted, groupTargeted, permission); }

        /**
         * Creates a new event args object, for where a permission is added to the default permissions.
         * @param registry The registry the event this event args object is for belongs to.
         * @param permissionAssigned The permission that was added to the default permissions.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
        }

        /**
         * Creates a new event args object, for where a user is directly assigned a permission.
         * @param registry The registry the event this event args object is for belongs to.
         * @param userId The ID of the user that was assigned a permission.
         * @param permissionAssigned The permission that was assigned to the user.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, permissionAssigned);
        }

        /**
         * Creates a new event args object, for where a group is directly assigned a permission.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupId The ID of the group that was assigned a permission.
         * @param permissionAssigned The permission that was assigned to the group.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupId, permissionAssigned);
        }
    }

    /**
     * Event args for when a permission is revoked.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class PermissionRevokedEventArgs<ID extends Comparable<? super ID>>
            extends PermissionEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
         *                      directly targeted, this should always be null.
         * @param permission The permission that was revoked in the action that raised this event.
         */
        protected PermissionRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                             PermissionsChangedTarget target,
                                             ID userTargeted,
                                             String groupTargeted,
                                             String permission)
        { super(registry, target, userTargeted, groupTargeted, permission); }

        /**
         * Creates a new event args object, for where a permission is removed from the default permissions.
         * @param registry The registry the event this event args object is for belongs to.
         * @param permissionAssigned The permission that was removed from the default permissions.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
        }

        /**
         * Creates a new event args object, for where a permission is directly revoked from a user.
         * @param registry The registry the event this event args object is for belongs to.
         * @param userId The ID of the user that had a permission revoked.
         * @param permissionAssigned The permission that was revoked from the user.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, permissionAssigned);
        }

        /**
         * Creates a new event args object, for where a permission is directly revoked from a group.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupId The ID of the group that had a permission revoked.
         * @param permissionAssigned The permission that was revoked from the group.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupId, permissionAssigned);
        }
    }

    /**
     * Event args for when a group is assigned or revoked.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class GroupEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        /**
         * The ID of the group associated with the action that raised this event. Where a group is targeted, this isn't
         * the group that was targeted, but rather the group that was assigned/revoked to/from that group.
         */
        final String groupId;

        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
         *                      directly targeted, this should always be null.
         * @param groupId The ID of the group associated with (not targeted by) the action that raised the event.
         */
        protected GroupEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                 PermissionsChangedTarget target,
                                 ID userTargeted,
                                 String groupTargeted,
                                 String groupId)
        {
            super(registry, target, userTargeted, groupTargeted);
            this.groupId = groupId;
        }

        /**
         * Gets the ID of the group associated with the action that raised this event. Where a group is targeted, this
         * isn't the group that was targeted,but rather the group that was assigned/revoked to/from that group.
         * @return The group associated with the action that raised the event.
         */
        public String getGroupAssociatedId()
        { return groupId; }
    }

    /**
     * Event args for when a group is assigned.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class GroupAssignedEventArgs<ID extends Comparable<? super ID>>
            extends GroupEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargetedId Where a group is being targeted, the ID of the group that was targeted. If a group was
         *                        not directly targeted, this should always be null.
         * @param groupAssignedId The ID of the group that was assigned in the action that raised this event.
         */
        protected GroupAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                         PermissionsChangedTarget target,
                                         ID userTargeted,
                                         String groupTargetedId,
                                         String groupAssignedId)
        { super(registry, target, userTargeted, groupTargetedId, groupAssignedId); }

        /**
         * Creates a new event args object, for where a group is added to the default permissions.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupAssignedId The ID of the group that was added to the default permissions.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, groupAssignedId);
        }

        /**
         * Creates a new event args object, for where a user is directly assigned a group.
         * @param registry The registry the event this event args object is for belongs to.
         * @param userId The ID of the user that was assigned a permission.
         * @param groupAssignedId The ID of the group that was assigned to the user.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, groupAssignedId);
        }

        /**
         * Creates a new event args object, for where a group is directly assigned a group.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupTargetedId The ID of the group that was assigned a group.
         * @param groupAssignedId The ID of the group that was assigned to the targeted group.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupTargetedId, groupAssignedId);
        }
    }

    /**
     * Event args for when a group is revoked.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class GroupRevokedEventArgs<ID extends Comparable<? super ID>>
            extends GroupEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this eventargs object is being created for belongs to.
         * @param target The type of entry in the registry that is being directly targeted.
         * @param userTargeted Where a user is being targeted, the user that was targeted. If a user was not directly
         *                     targeted, this should always be null.
         * @param groupTargetedId Where a group is being targeted, the group that was targeted. If a group was not
         *                        directly targeted, this should always be null.
         * @param groupRevokedId The group that was revoked in the action that raised this event.
         */
        protected GroupRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                        PermissionsChangedTarget target,
                                        ID userTargeted,
                                        String groupTargetedId,
                                        String groupRevokedId)
        { super(registry, target, userTargeted, groupTargetedId, groupRevokedId); }

        /**
         * Creates a new event args object, for where a group is removed from to the default permissions.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupRevokedId The ID of the group that was removed from the default permissions.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, groupRevokedId);
        }

        /**
         * Creates a new event args object, for where a group is directly revoked from a user.
         * @param registry The registry the event this event args object is for belongs to.
         * @param userId The ID of the user that had a group revoked.
         * @param groupRevokedId The ID of the group that was revoked from the user.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, groupRevokedId);
        }

        /**
         * Creates a new event args object, for where a group is directly revoked from a group.
         * @param registry The registry the event this event args object is for belongs to.
         * @param groupTargetedId The ID of the group that had a group revoked.
         * @param groupRevokedId The ID of the group that was revoked from the targeted group.
         * @param <ID> The type users in the registry are identified by.
         * @return A new event args object.
         */
        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupTargetedId, groupRevokedId);
        }
    }

    /**
     * Event args for when the registry is cleared.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class ClearedEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this event args object is for belongs to.
         */
        protected ClearedEventArgs(PermissionsRegistryWithEvents<ID> registry)
        { super(registry, PermissionsChangedTarget.ALL, null, null); }
    }

    /**
     * Event args for when the contents of the registry are replaced with contents from a file.
     * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
     *             to.
     */
    public static class LoadedEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        /**
         * Creates a new event args object.
         * @param registry The registry the event this event args object is for belongs to.
         */
        protected LoadedEventArgs(PermissionsRegistryWithEvents<ID> registry)
        { super(registry, PermissionsChangedTarget.ALL, null, null); }
    }
    //endregion
    //endregion

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
    protected final InvokableEvent<GroupAssignedEventArgs<ID>> groupAssigned_internal = new SetEvent<>();

    /**
     * Fired when a group is revoked from something.
     */
    protected final InvokableEvent<GroupRevokedEventArgs<ID>> groupRevoked_internal = new SetEvent<>();

    /**
     * Fired when the registry is cleared.
     */
    protected final InvokableEvent<ClearedEventArgs<ID>> cleared_internal = new SetEvent<>();

    /**
     * Fired when the registry's contents are replaced with the contents as loaded from a file.
     */
    protected final InvokableEvent<LoadedEventArgs<ID>> loaded_internal = new SetEvent<>();

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
    protected final InvokableEvent<ContentsChangedEventArgs<ID>> contentsChanged_internal = new SetEvent<>();
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
    public final Event<GroupAssignedEventArgs<ID>> groupAssigned = new ProtectedEvent<>(groupAssigned_internal);

    /**
     * Fired when a group is revoked from something.
     */
    public final Event<GroupRevokedEventArgs<ID>> groupRevoked = new ProtectedEvent<>(groupRevoked_internal);

    /**
     * Fired when the registry is cleared.
     */
    public final Event<ClearedEventArgs<ID>> cleared = new ProtectedEvent<>(cleared_internal);

    /**
     * Fired when the registry's contents are replaced with the contents as loaded from a file.
     */
    public final Event<LoadedEventArgs<ID>> loaded = new ProtectedEvent<>(loaded_internal);

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
    public final Event<ContentsChangedEventArgs<ID>> contentsChanged = new ProtectedEvent<>(contentsChanged_internal);
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
    public boolean revokeUserPermission(ID userId, String permission)
    {
        boolean result = super.revokeUserPermission(userId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutUser(this, userId, permission));
        return result;
    }

    @Override
    public boolean revokeGroupPermission(String groupId, String permission)
    {
        boolean result = super.revokeGroupPermission(groupId, permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutGroup(this, groupId, permission));
        return result;
    }

    @Override
    public boolean revokeDefaultPermission(String permission)
    {
        boolean result = super.revokeDefaultPermission(permission);
        permissionRevoked_internal.invoke(PermissionRevokedEventArgs.newAboutDefaultPermissions(this, permission));
        return result;
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        super.assignGroupToUser(userId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(GroupAssignedEventArgs.newAboutUser(this, userId, groupIdBeingAssigned));
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        super.assignGroupToGroup(groupId, groupIdBeingAssigned);
        groupAssigned_internal.invoke(GroupAssignedEventArgs.newAboutGroup(this, groupId, groupIdBeingAssigned));
    }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    {
        super.assignDefaultGroup(groupIdBeingAssigned);
        groupAssigned_internal.invoke(GroupAssignedEventArgs.newAboutDefaultPermissions(this, groupIdBeingAssigned));
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromUser(userId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(GroupRevokedEventArgs.newAboutUser(this, userId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromGroup(groupId, groupIdBeingRevoked);
        groupRevoked_internal.invoke(GroupRevokedEventArgs.newAboutGroup(this, groupId, groupIdBeingRevoked));
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    {
        boolean result = super.revokeDefaultGroup(groupIdBeingRevoked);
        groupRevoked_internal.invoke(GroupRevokedEventArgs.newAboutDefaultPermissions(this, groupIdBeingRevoked));
        return result;
    }

    @Override
    public void clear()
    {
        super.clear();
        cleared_internal.invoke(new ClearedEventArgs<>(this));
    }

    @Override
    public void load() throws IOException
    {
        super.load();
        loaded_internal.invoke(new LoadedEventArgs<>(this));
    }
    //endregion
}
