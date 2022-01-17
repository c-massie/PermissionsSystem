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

    //region boolean userHasPermission(ID userId, String permission)
    BiCache<ID, String, Boolean> uHasPermissionCache = new BiCache<>(inner::userHasPermission);

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { return uHasPermissionCache.get(userId, permission); }
    //endregion

    //region groupHasPermission(String groupName, String permission)
    BiCache<String, String, Boolean> gHasPermissionCache = new BiCache<>(inner::groupHasPermission);

    @Override
    public boolean groupHasPermission(String groupName, String permission)
    { return gHasPermissionCache.get(groupName, permission); }
    //endregion

    //region isDefaultPermission(String permission)
    Cache<String, Boolean> dHasPermissionCache = new Cache<>(inner::isDefaultPermission);

    @Override
    public boolean isDefaultPermission(String permission)
    { return dHasPermissionCache.get(permission); }
    //endregion

    //region userHasAllPermissions(ID userId, Iterable<String> permissions)
    BiCache<ID, Iterable<String>, Boolean> uHasAllPermsCache = new BiCache<>(inner::userHasAllPermissions);

    @Override
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    { return uHasAllPermsCache.get(userId, permissions); }

    @Override
    public boolean userHasAllPermissions(ID userId, String... permissions)
    { return userHasAllPermissions(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAllPermissions(String groupName, Iterable<String> permissions)
    BiCache<String, Iterable<String>, Boolean> gHasAllPermsCache = new BiCache<>(inner::groupHasAllPermissions);

    @Override
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    { return gHasAllPermsCache.get(groupName, permissions); }

    @Override
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    { return groupHasAllPermissions(groupName, Arrays.asList(permissions)); }
    //endregion

    //region areAllDefaultPermissions(Iterable<String> permissions)
    Cache<Iterable<String>, Boolean> dHasAllPermsCache = new Cache<>(inner::areAllDefaultPermissions);

    @Override
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    { return dHasAllPermsCache.get(permissions); }

    @Override
    public boolean areAllDefaultPermissions(String... permissions)
    { return areAllDefaultPermissions(Arrays.asList(permissions)); }
    //endregion

    //region userHasAnyPermissions(ID userId, Iterable<String> permissions)
    BiCache<ID, Iterable<String>, Boolean> uHasAnyPermsCache = new BiCache<>(inner::userHasAnyPermissions);

    @Override
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    { return uHasAnyPermsCache.get(userId, permissions); }

    @Override
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    { return userHasAnyPermissions(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    BiCache<String, Iterable<String>, Boolean> gHasAnyPermsCache = new BiCache<>(inner::groupHasAnyPermissions);

    @Override
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    { return gHasAnyPermsCache.get(groupName, permissions); }

    @Override
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    { return groupHasAnyPermissions(groupName, Arrays.asList(permissions)); }
    //endregion

    //region anyAreDefaultPermissions(Iterable<String> permissions)
    Cache<Iterable<String>, Boolean> dHasAnyPermsCache = new Cache<>(inner::anyAreDefaultPermissions);

    @Override
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    { return dHasAnyPermsCache.get(permissions); }

    @Override
    public boolean anyAreDefaultPermissions(String... permissions)
    { return anyAreDefaultPermissions(Arrays.asList(permissions)); }
    //endregion

    //region userHasAnySubPermissionOf(ID userId, String permission)
    BiCache<ID, String, Boolean> uHasAnySubPermsOfCache = new BiCache<>(inner::userHasAnySubPermissionOf);

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return uHasAnySubPermsOfCache.get(userId, permission); }
    //endregion

    //region userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    BiCache<ID, Iterable<String>, Boolean> uHasAnySubPermsOfMultipleCache = new BiCache<>(inner::userHasAnySubPermissionOf);

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    { return uHasAnySubPermsOfMultipleCache.get(userId, permissions); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    { return userHasAnySubPermissionOf(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAnySubPermissionOf(String groupId, String permission)
    BiCache<String, String, Boolean> gHasAnySubPermsOfCache = new BiCache<>(inner::groupHasAnySubPermissionOf);

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { return gHasAnySubPermsOfCache.get(groupId, permission); }
    //endregion

    //region groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    BiCache<String, Iterable<String>, Boolean> gHasAnySubPermsOfMultipleCache = new BiCache<>(inner::groupHasAnySubPermissionOf);

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    { return gHasAnySubPermsOfMultipleCache.get(groupId, permissions); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    { return groupHasAnySubPermissionOf(groupId, Arrays.asList(permissions)); }
    //endregion

    //region isOrAnySubPermissionOfIsDefault(String permission)
    Cache<String, Boolean> dHasAnySubPermsOfCache = new Cache<>(inner::isOrAnySubPermissionOfIsDefault);

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { return dHasAnySubPermsOfCache.get(permission); }
    //endregion

    //region isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    Cache<Iterable<String>, Boolean> dHasAnySubPermsOfMultipleCache = new Cache<>(inner::isOrAnySubPermissionOfIsDefault);

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    { return dHasAnySubPermsOfMultipleCache.get(permissions); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    { return isOrAnySubPermissionOfIsDefault(Arrays.asList(permissions)); }
    //endregion

    //region getUserPermissionArg(ID userId, String permission)
    BiCache<ID, String, String> uPArgCache = new BiCache<>(inner::getUserPermissionArg);

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    { return uPArgCache.get(userId, permission); }
    //endregion

    //region getGroupPermissionArg(String groupId, String permission)
    BiCache<String, String, String> gPArgCache = new BiCache<>(inner::getGroupPermissionArg);

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    { return gPArgCache.get(groupId, permission); }
    //endregion

    //region getDefaultPermissionArg(String permission)
    Cache<String, String> dPArgCache = new Cache<>(inner::getDefaultPermissionArg);

    @Override
    public String getDefaultPermissionArg(String permission)
    { return dPArgCache.get(permission); }
    //endregion

    //region userHasGroup(ID userId, String groupName)
    BiCache<ID, String, Boolean> uHasGroupCache = new BiCache<>(inner::userHasGroup);

    @Override
    public boolean userHasGroup(ID userId, String groupName)
    { return uHasGroupCache.get(userId, groupName); }
    //endregion

    //region groupExtendsFromGroup(String groupId, String superGroupName)
    BiCache<String, String, Boolean> gHasGroupCache = new BiCache<>(inner::groupExtendsFromGroup);

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    { return gHasGroupCache.get(groupId, superGroupName); }
    //endregion

    //region isDefaultGroup(String groupId)
    Cache<String, Boolean> dHasGroupCache = new Cache<>(inner::isDefaultGroup);

    @Override
    public boolean isDefaultGroup(String groupId)
    { return dHasGroupCache.get(groupId); }
    //endregion

    //region userHasAllGroups(ID userId, Iterable<String> groupNames)
    BiCache<ID, Iterable<String>, Boolean> uHasAllGroupsCache = new BiCache<>(inner::userHasAllGroups);

    @Override
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    { return uHasAllGroupsCache.get(userId, groupNames); }

    @Override
    public boolean userHasAllGroups(ID userId, String... groupNames)
    { return userHasAllGroups(userId, Arrays.asList(groupNames)); }
    //endregion

    //region groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    BiCache<String, Iterable<String>, Boolean> gHasAllGroupsCache = new BiCache<>(inner::groupExtendsFromAllGroups);

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    { return gHasAllGroupsCache.get(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    { return groupExtendsFromAllGroups(groupName, Arrays.asList(superGroupNames)); }
    //endregion

    //region areAllDefaultGroups(Iterable<String> groupNames)
    Cache<Iterable<String>, Boolean> dHasAllGroupsCache = new Cache<>(inner::areAllDefaultGroups);

    @Override
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    { return dHasAllGroupsCache.get(groupNames); }

    @Override
    public boolean areAllDefaultGroups(String... groupNames)
    { return areAllDefaultGroups(Arrays.asList(groupNames)); }
    //endregion

    //region userHasAnyGroups(ID userId, Iterable<String> groupNames)
    BiCache<ID, Iterable<String>, Boolean> uHasAnyGroupsCache = new BiCache<>(inner::userHasAnyGroups);

    @Override
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    { return uHasAnyGroupsCache.get(userId, groupNames); }

    @Override
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    { return userHasAnyGroups(userId, Arrays.asList(groupNames)); }
    //endregion

    //region groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    BiCache<String, Iterable<String>, Boolean> gHasAnyGroupsCache = new BiCache<>(inner::groupExtendsFromAnyGroups);

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    { return gHasAnyGroupsCache.get(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    { return groupExtendsFromAnyGroups(groupName, Arrays.asList(superGroupNames)); }
    //endregion

    //region anyAreDefaultGroups(Iterable<String> groupNames)
    Cache<Iterable<String>, Boolean> dHasAnyGroupsCache = new Cache<>(inner::anyAreDefaultGroups);

    @Override
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    { return dHasAnyGroupsCache.get(groupNames); }

    @Override
    public boolean anyAreDefaultGroups(String... groupNames)
    { return anyAreDefaultGroups(Arrays.asList(groupNames)); }
    //endregion
}
