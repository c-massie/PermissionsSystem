package scot.massie.lib.permissions.decorators;

import scot.massie.lib.collections.iterables.queues.EvictingHashMap;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.EventArgs;
import scot.massie.lib.permissions.PermissionStatus;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

public class CachedPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    // NOTE: Assertions are not cached.

    private class Cache<TArg, TResult>
    {
        EvictingHashMap<TArg, TResult> cachedValues = null;

        Function<TArg, TResult> resultGetter;

        public Cache(Function<TArg, TResult> function)
        {
            this.resultGetter = function;
            CachedPermissionsRegistry.this.cacheInvalidated.register(this::invalidate);
        }

        public TResult get(TArg arg)
        {
            if(cachedValues == null)
                return (cachedValues = new EvictingHashMap<>()).put(arg, resultGetter.apply(arg));

            return cachedValues.computeIfAbsent(arg, x -> resultGetter.apply(x));
        }

        public void invalidate()
        { cachedValues = null; }
    }

    private class BiCache<TArg1, TArg2, TResult>
    {
        EvictingHashMap<TArg1, EvictingHashMap<TArg2, TResult>> cachedValues = null;

        BiFunction<TArg1, TArg2, TResult> resultGetter;

        public BiCache(BiFunction<TArg1, TArg2, TResult> function)
        {
            this.resultGetter = function;
            CachedPermissionsRegistry.this.cacheInvalidated.register(this::invalidate);
        }

        public TResult get(TArg1 arg1, TArg2 arg2)
        {
            if(cachedValues == null)
            {
                return (cachedValues = new EvictingHashMap<>())
                        .put(arg1, new EvictingHashMap<>())
                        .put(arg2, resultGetter.apply(arg1, arg2));
            }

            return cachedValues.computeIfAbsent(arg1, x -> new EvictingHashMap<>())
                               .computeIfAbsent(arg2, x -> resultGetter.apply(arg1, arg2));
        }

        public void invalidate()
        { cachedValues = null; }
    }

    private final InvokableEvent<EventArgs> cacheInvalidated = new SetEvent<>();

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
    { cacheInvalidated.invoke(null); }

    //region getUserPermissionStatus(ID userId, String permission) { ... }
    BiCache<ID, String, PermissionStatus> uPStatusCache = new BiCache<>(inner::getUserPermissionStatus);

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return uPStatusCache.get(userId, permission); }
    //endregion

    //region getGroupPermissionStatus(String groupName, String permission) { ... }
    BiCache<String, String, PermissionStatus> gPStatusCache = new BiCache<>(inner::getGroupPermissionStatus);

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    { return gPStatusCache.get(groupName, permission); }
    //endregion

    //region getDefaultPermissionStatus(String permission) { ... }
    Cache<String, PermissionStatus> dPStatusCache = new Cache<>(inner::getDefaultPermissionStatus);

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { return dPStatusCache.get(permission); }
    //endregion

    //region getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    BiCache<ID, Iterable<String>, Map<String, PermissionStatus>> uPStatusesCache
            = new BiCache<>((a, b) -> Collections.unmodifiableMap(inner.getUserPermissionStatuses(a, b)));

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    { return uPStatusesCache.get(userId, permissions); }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    { return getUserPermissionStatuses(userId, Arrays.asList(permissions)); }
    //endregion

    //region getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    BiCache<String, Iterable<String>, Map<String, PermissionStatus>> gPStatusesCache
            = new BiCache<>((a, b) -> Collections.unmodifiableMap(inner.getGroupPermissionStatuses(a, b)));

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    { return gPStatusesCache.get(groupName, permissions); }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    { return getGroupPermissionStatuses(groupName, Arrays.asList(permissions)); }
    //endregion

    //region getDefaultPermissionStatuses(Iterable<String> permissions)
    Cache<Iterable<String>, Map<String, PermissionStatus>> dPStatusesCache
            = new Cache<>(x -> Collections.unmodifiableMap(inner.getDefaultPermissionStatuses(x)));

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    { return dPStatusesCache.get(permissions); }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    { return getDefaultPermissionStatuses(Arrays.asList(permissions)); }
    //endregion

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
