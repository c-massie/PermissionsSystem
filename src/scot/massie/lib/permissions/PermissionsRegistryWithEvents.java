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
    public enum PermissionsChangedTarget
    { ALL, USER, GROUP, DEFAULT_PERMISSIONS }

    //region EventArgs types
    /**
     * Event args for when the contents of the permissions registry change.
     */
    public static class ContentsChangedEventArgs<ID extends Comparable<? super ID>> implements EventArgs
    {
        final PermissionsRegistryWithEvents<ID> registry;
        final PermissionsChangedTarget target;
        final ID userTargeted;
        final String groupTargeted;

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

        public PermissionsChangedTarget getTarget()
        { return target; }

        public ID getUserTargeted()
        { return userTargeted; }

        public String getGroupTargetedId()
        { return groupTargeted; }

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

    public static class PermissionEventArgs<ID extends Comparable<? super ID>>
            extends ContentsChangedEventArgs<ID>
    {
        final String permission;

        protected PermissionEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                      PermissionsChangedTarget target,
                                      ID userTargeted,
                                      String groupTargeted,
                                      String permission)
        {
            super(registry, target, userTargeted, groupTargeted);
            this.permission = permission;
        }

        public String getPermission()
        { return permission; }
    }

    public static class PermissionAssignedEventArgs<ID extends Comparable<? super ID>>
            extends PermissionEventArgs<ID>
    {
        protected PermissionAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                              PermissionsChangedTarget target,
                                              ID userTargeted,
                                              String groupTargeted,
                                              String permission)
        { super(registry, target, userTargeted, groupTargeted, permission); }

        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
        }

        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, permissionAssigned);
        }

        static <ID extends Comparable<? super ID>> PermissionAssignedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
        {
            return new PermissionAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupId, permissionAssigned);
        }
    }

    public static class PermissionRevokedEventArgs<ID extends Comparable<? super ID>>
            extends PermissionEventArgs<ID>
    {
        protected PermissionRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                             PermissionsChangedTarget target,
                                             ID userTargeted,
                                             String groupTargeted,
                                             String permission)
        { super(registry, target, userTargeted, groupTargeted, permission); }

        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, permissionAssigned);
        }

        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, permissionAssigned);
        }

        static <ID extends Comparable<? super ID>> PermissionRevokedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupId, String permissionAssigned)
        {
            return new PermissionRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupId, permissionAssigned);
        }
    }

    public static class GroupEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        final String groupId;

        protected GroupEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                 PermissionsChangedTarget target,
                                 ID userTargeted,
                                 String groupTargeted,
                                 String groupId)
        {
            super(registry, target, userTargeted, groupTargeted);
            this.groupId = groupId;
        }

        public String getGroupAssociatedId()
        { return groupId; }
    }

    public static class GroupAssignedEventArgs<ID extends Comparable<? super ID>>
            extends GroupEventArgs<ID>
    {
        protected GroupAssignedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                         PermissionsChangedTarget target,
                                         ID userTargeted,
                                         String groupTargeted,
                                         String groupId)
        { super(registry, target, userTargeted, groupTargeted, groupId); }

        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, groupAssignedId);
        }

        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, groupAssignedId);
        }

        static <ID extends Comparable<? super ID>> GroupAssignedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupAssignedId)
        {
            return new GroupAssignedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupTargetedId, groupAssignedId);
        }
    }

    public static class GroupRevokedEventArgs<ID extends Comparable<? super ID>>
            extends GroupEventArgs<ID>
    {
        protected GroupRevokedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                        PermissionsChangedTarget target,
                                        ID userTargeted,
                                        String groupTargeted,
                                        String groupId)
        { super(registry, target, userTargeted, groupTargeted, groupId); }

        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutDefaultPermissions(PermissionsRegistryWithEvents<ID> registry, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.DEFAULT_PERMISSIONS, null, null, groupRevokedId);
        }

        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutUser(PermissionsRegistryWithEvents<ID> registry, ID userId, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.USER, userId, null, groupRevokedId);
        }

        static <ID extends Comparable<? super ID>> GroupRevokedEventArgs<ID>
        newAboutGroup(PermissionsRegistryWithEvents<ID> registry, String groupTargetedId, String groupRevokedId)
        {
            return new GroupRevokedEventArgs<>(
                    registry, PermissionsChangedTarget.GROUP, null, groupTargetedId, groupRevokedId);
        }
    }

    public static class ClearedEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        protected ClearedEventArgs(PermissionsRegistryWithEvents<ID> registry)
        { super(registry, PermissionsChangedTarget.ALL, null, null); }
    }

    public static class LoadedEventArgs<ID extends Comparable<? super ID>> extends ContentsChangedEventArgs<ID>
    {
        protected LoadedEventArgs(PermissionsRegistryWithEvents<ID> registry)
        { super(registry, PermissionsChangedTarget.ALL, null, null); }
    }
    //endregion
    //endregion

    //region events
    //region internal events
    protected final InvokableEvent<PermissionAssignedEventArgs<ID>> permissionAssigned_internal = new SetEvent<>();

    protected final InvokableEvent<PermissionRevokedEventArgs<ID>> permissionRevoked_internal = new SetEvent<>();

    protected final InvokableEvent<GroupAssignedEventArgs<ID>> groupAssigned_internal = new SetEvent<>();

    protected final InvokableEvent<GroupRevokedEventArgs<ID>> groupRevoked_internal = new SetEvent<>();

    protected final InvokableEvent<ClearedEventArgs<ID>> cleared_internal = new SetEvent<>();

    protected final InvokableEvent<LoadedEventArgs<ID>> loaded_internal = new SetEvent<>();

    /**
     * Fired when the contents of the permissions registry are changed.
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
     * Fired when the contents of the permissions registry are changed.
     */
    public final Event<ContentsChangedEventArgs<ID>> contentsChanged = new ProtectedEvent<>(contentsChanged_internal);

    public final Event<PermissionAssignedEventArgs<ID>> permissionAssigned = new ProtectedEvent<>(permissionAssigned_internal);

    public final Event<PermissionRevokedEventArgs<ID>> permissionRevoked = new ProtectedEvent<>(permissionRevoked_internal);

    public final Event<GroupAssignedEventArgs<ID>> groupAssigned = new ProtectedEvent<>(groupAssigned_internal);

    public final Event<GroupRevokedEventArgs<ID>> groupRevoked = new ProtectedEvent<>(groupRevoked_internal);

    public final Event<ClearedEventArgs<ID>> cleared = new ProtectedEvent<>(cleared_internal);

    public final Event<LoadedEventArgs<ID>> loaded = new ProtectedEvent<>(loaded_internal);
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
