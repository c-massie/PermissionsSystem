package scot.massie.lib.permissions.decorators;

import scot.massie.lib.collections.maps.EvictingHashMap;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.EventArgs;
import scot.massie.lib.permissions.GroupMapPermissionsRegistry;
import scot.massie.lib.permissions.Permission;
import scot.massie.lib.permissions.PermissionStatus;
import scot.massie.lib.permissions.PermissionsRegistry;
import scot.massie.lib.permissions.PermissionsRegistryDecorator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * <p>A {@link PermissionsRegistry} decorator that stores the results of accessor calls and returning stored results
 * from accessor calls where applicable, only refreshing stored results when the contents changes.</p>
 * @see PermissionsRegistry
 * @apiNote This assumes that the contents of the contained permissions registry is static when not calling any of the
 *          standard permissions registry mutators, and that the contained registry is not mutated from outwith this
 *          decorator. If this is not the case, this decorator should not be used, as this can lead to caches becoming
 *          outdated without being invalidated.
 * @param <ID> The type of the unique identifier used to represent users.
 */
public final class CachedPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistryDecorator<ID>
{
    // NOTE: Assertions are not cached.

    //region Subclasses

    /**
     * Cache for single-argument accessors. This encapsulates a function and stores the result when queried.
     * @param <TArg> The argument type.
     * @param <TResult> The type returned.
     */
    private class Cache<TArg, TResult>
    {
        /**
         * The map of cached results against the single argument passed in.
         */
        EvictingHashMap<TArg, TResult> cachedValues = null;

        /**
         * The encapsulated function.
         */
        Function<TArg, TResult> resultGetter;

        /**
         * Creates a new cache.
         * @param function The function that this cache should call and cache the result of.
         */
        public Cache(Function<TArg, TResult> function)
        {
            this.resultGetter = function;
            cacheInvalidated.register(this::invalidate);
        }

        /**
         * Gets the result of the encapsulated function. If a result for the given arg already exists in this cache,
         * retrieves the result from the cache instead of calling the function again. Otherwise, calls the encapsulated
         * function with the given arg, stores the result, and returns the result.
         * @param arg The arg to pass into the encapsulated function.
         * @return The result of calling the encapsulated function with the given argument.
         */
        public TResult get(TArg arg)
        {
            if(cachedValues == null)
            {
                cachedValues = new EvictingHashMap<>(cacheSize);
                TResult result = resultGetter.apply(arg);
                cachedValues.put(arg, result);
                return result;
            }

            return cachedValues.computeIfAbsent(arg, x -> resultGetter.apply(x));
        }

        /**
         * Wipes the stored results of this cache.
         */
        public void invalidate()
        { cachedValues = null; }
    }

    /**
     * Cache for dual-argument accessors. This encapsulates a function and stores the result when queried.
     * @param <TArg1> The first argument type.
     * @param <TArg2> The second argument type.
     * @param <TResult> The type returned.
     */
    private class BiCache<TArg1, TArg2, TResult>
    {
        /**
         * The map of cached results against the single argument passed in.
         */
        EvictingHashMap<TArg1, EvictingHashMap<TArg2, TResult>> cachedValues = null;

        /**
         * The encapsulated function.
         */
        BiFunction<TArg1, TArg2, TResult> resultGetter;

        /**
         * Creates a new cache.
         * @param function The function that this cache should call and cache the result of.
         */
        public BiCache(BiFunction<TArg1, TArg2, TResult> function)
        {
            this.resultGetter = function;
            cacheInvalidated.register(this::invalidate);
        }

        /**
         * Gets the result of the encapsulated function. If a result for the given arg already exists in this cache,
         * retrieves the result from the cache instead of calling the function again. Otherwise, calls the encapsulated
         * function with the given args, stores the result, and returns the result.
         * @param arg1 The first arg to pass into the encapsulated function.
         * @param arg2 The second arg to pass into the encapsulated function.
         * @return The result of calling the encapsulated function with the given arguments.
         */
        public TResult get(TArg1 arg1, TArg2 arg2)
        {
            if(cachedValues == null)
            {
                cachedValues                            = new EvictingHashMap<>(cacheSize);
                EvictingHashMap<TArg2, TResult> arg1Map = new EvictingHashMap<>(cacheSize);
                TResult result                          = resultGetter.apply(arg1, arg2);

                cachedValues.put(arg1, arg1Map);
                arg1Map.put(arg2, result);
                return result;
            }

            return cachedValues.computeIfAbsent(arg1, x -> new EvictingHashMap<>())
                               .computeIfAbsent(arg2, x -> resultGetter.apply(arg1, arg2));
        }

        /**
         * Wipes the stored results of this cache.
         */
        public void invalidate()
        { cachedValues = null; }
    }
    //endregion

    //region Instance variables
    private final int cacheSize = 20;
    //endregion

    //region Events
    /**
     * Event that's fired by calling {@link #invalidateCache()} - caches for accessors listen to this event and wipe
     * when it fires.
     */
    private final InvokableEvent<EventArgs> cacheInvalidated = new SetEvent<>();
    //endregion

    //region initialisation
    /**
     * Creates a new cached permissions registry, with the ability to save to/load from files. This is the equivalent of
     * passing a new instance of {@link GroupMapPermissionsRegistry} created with the given arguments into
     * {@link #CachedPermissionsRegistry(PermissionsRegistry)}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public CachedPermissionsRegistry(Function<ID, String> idToString,
                                     Function<String, ID> idFromString,
                                     Path usersFile,
                                     Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new cached permissions registry, without the ability to save to/load from files. This is the equivalent
     * of passing a new instance of {@link GroupMapPermissionsRegistry} created with the given arguments into
     * {@link #CachedPermissionsRegistry(PermissionsRegistry)}.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public CachedPermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    /**
     * Wraps an existing permissions registry in a cached permissions registry, providing access to it that caches
     * accessor call results.
     * @param inner The wrapped permissions registry.
     */
    public CachedPermissionsRegistry(PermissionsRegistry<ID> inner)
    { super(inner); }
    //endregion

    //region methods

    /**
     * Deletes the caches for all accessors of this permissions registry.
     */
    public void invalidateCache()
    { cacheInvalidated.invoke(null); }

    //region PermissionRegistry methods
    //region Accessors
    //region getUserPermissionStatus(ID userId, String permission) { ... }
    private final BiCache<ID, String, PermissionStatus> uPStatusCache = new BiCache<>(inner::getUserPermissionStatus);

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return uPStatusCache.get(userId, permission); }
    //endregion

    //region getGroupPermissionStatus(String groupName, String permission) { ... }
    private final BiCache<String, String, PermissionStatus> gPStatusCache = new BiCache<>(inner::getGroupPermissionStatus);

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    { return gPStatusCache.get(groupName, permission); }
    //endregion

    //region getDefaultPermissionStatus(String permission) { ... }
    private final Cache<String, PermissionStatus> dPStatusCache = new Cache<>(inner::getDefaultPermissionStatus);

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { return dPStatusCache.get(permission); }
    //endregion

    //region getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    private final BiCache<ID, Iterable<String>, Map<String, PermissionStatus>> uPStatusesCache
            = new BiCache<>((a, b) -> Collections.unmodifiableMap(inner.getUserPermissionStatuses(a, b)));

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    { return uPStatusesCache.get(userId, permissions); }

    @Override
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    { return getUserPermissionStatuses(userId, Arrays.asList(permissions)); }
    //endregion

    //region getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    private final BiCache<String, Iterable<String>, Map<String, PermissionStatus>> gPStatusesCache
            = new BiCache<>((a, b) -> Collections.unmodifiableMap(inner.getGroupPermissionStatuses(a, b)));

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    { return gPStatusesCache.get(groupName, permissions); }

    @Override
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    { return getGroupPermissionStatuses(groupName, Arrays.asList(permissions)); }
    //endregion

    //region getDefaultPermissionStatuses(Iterable<String> permissions)
    private final Cache<Iterable<String>, Map<String, PermissionStatus>> dPStatusesCache
            = new Cache<>(x -> Collections.unmodifiableMap(inner.getDefaultPermissionStatuses(x)));

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    { return dPStatusesCache.get(permissions); }

    @Override
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    { return getDefaultPermissionStatuses(Arrays.asList(permissions)); }
    //endregion

    //region boolean userHasPermission(ID userId, String permission)
    private final BiCache<ID, String, Boolean> uHasPermissionCache = new BiCache<>(inner::userHasPermission);

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { return uHasPermissionCache.get(userId, permission); }
    //endregion

    //region groupHasPermission(String groupName, String permission)
    private final BiCache<String, String, Boolean> gHasPermissionCache = new BiCache<>(inner::groupHasPermission);

    @Override
    public boolean groupHasPermission(String groupName, String permission)
    { return gHasPermissionCache.get(groupName, permission); }
    //endregion

    //region isDefaultPermission(String permission)
    private final Cache<String, Boolean> dHasPermissionCache = new Cache<>(inner::isDefaultPermission);

    @Override
    public boolean isDefaultPermission(String permission)
    { return dHasPermissionCache.get(permission); }
    //endregion

    //region userHasAllPermissions(ID userId, Iterable<String> permissions)
    private final BiCache<ID, Iterable<String>, Boolean> uHasAllPermsCache = new BiCache<>(inner::userHasAllPermissions);

    @Override
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    { return uHasAllPermsCache.get(userId, permissions); }

    @Override
    public boolean userHasAllPermissions(ID userId, String... permissions)
    { return userHasAllPermissions(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAllPermissions(String groupName, Iterable<String> permissions)
    private final BiCache<String, Iterable<String>, Boolean> gHasAllPermsCache = new BiCache<>(inner::groupHasAllPermissions);

    @Override
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    { return gHasAllPermsCache.get(groupName, permissions); }

    @Override
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    { return groupHasAllPermissions(groupName, Arrays.asList(permissions)); }
    //endregion

    //region areAllDefaultPermissions(Iterable<String> permissions)
    private final Cache<Iterable<String>, Boolean> dHasAllPermsCache = new Cache<>(inner::areAllDefaultPermissions);

    @Override
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    { return dHasAllPermsCache.get(permissions); }

    @Override
    public boolean areAllDefaultPermissions(String... permissions)
    { return areAllDefaultPermissions(Arrays.asList(permissions)); }
    //endregion

    //region userHasAnyPermissions(ID userId, Iterable<String> permissions)
    private final BiCache<ID, Iterable<String>, Boolean> uHasAnyPermsCache = new BiCache<>(inner::userHasAnyPermissions);

    @Override
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    { return uHasAnyPermsCache.get(userId, permissions); }

    @Override
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    { return userHasAnyPermissions(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    private final BiCache<String, Iterable<String>, Boolean> gHasAnyPermsCache = new BiCache<>(inner::groupHasAnyPermissions);

    @Override
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    { return gHasAnyPermsCache.get(groupName, permissions); }

    @Override
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    { return groupHasAnyPermissions(groupName, Arrays.asList(permissions)); }
    //endregion

    //region anyAreDefaultPermissions(Iterable<String> permissions)
    private final Cache<Iterable<String>, Boolean> dHasAnyPermsCache = new Cache<>(inner::anyAreDefaultPermissions);

    @Override
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    { return dHasAnyPermsCache.get(permissions); }

    @Override
    public boolean anyAreDefaultPermissions(String... permissions)
    { return anyAreDefaultPermissions(Arrays.asList(permissions)); }
    //endregion

    //region userHasAnySubPermissionOf(ID userId, String permission)
    private final BiCache<ID, String, Boolean> uHasAnySubPermsOfCache = new BiCache<>(inner::userHasAnySubPermissionOf);

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return uHasAnySubPermsOfCache.get(userId, permission); }
    //endregion

    //region userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    private final BiCache<ID, Iterable<String>, Boolean> uHasAnySubPermsOfMultipleCache = new BiCache<>(inner::userHasAnySubPermissionOf);

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    { return uHasAnySubPermsOfMultipleCache.get(userId, permissions); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    { return userHasAnySubPermissionOf(userId, Arrays.asList(permissions)); }
    //endregion

    //region groupHasAnySubPermissionOf(String groupId, String permission)
    private final BiCache<String, String, Boolean> gHasAnySubPermsOfCache = new BiCache<>(inner::groupHasAnySubPermissionOf);

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { return gHasAnySubPermsOfCache.get(groupId, permission); }
    //endregion

    //region groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    private final BiCache<String, Iterable<String>, Boolean> gHasAnySubPermsOfMultipleCache = new BiCache<>(inner::groupHasAnySubPermissionOf);

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    { return gHasAnySubPermsOfMultipleCache.get(groupId, permissions); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    { return groupHasAnySubPermissionOf(groupId, Arrays.asList(permissions)); }
    //endregion

    //region isOrAnySubPermissionOfIsDefault(String permission)
    private final Cache<String, Boolean> dHasAnySubPermsOfCache = new Cache<>(inner::isOrAnySubPermissionOfIsDefault);

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { return dHasAnySubPermsOfCache.get(permission); }
    //endregion

    //region isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    private final Cache<Iterable<String>, Boolean> dHasAnySubPermsOfMultipleCache = new Cache<>(inner::isOrAnySubPermissionOfIsDefault);

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    { return dHasAnySubPermsOfMultipleCache.get(permissions); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    { return isOrAnySubPermissionOfIsDefault(Arrays.asList(permissions)); }
    //endregion

    //region getUserPermissionArg(ID userId, String permission)
    private final BiCache<ID, String, String> uPArgCache = new BiCache<>(inner::getUserPermissionArg);

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    { return uPArgCache.get(userId, permission); }
    //endregion

    //region getGroupPermissionArg(String groupId, String permission)
    private final BiCache<String, String, String> gPArgCache = new BiCache<>(inner::getGroupPermissionArg);

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    { return gPArgCache.get(groupId, permission); }
    //endregion

    //region getDefaultPermissionArg(String permission)
    private final Cache<String, String> dPArgCache = new Cache<>(inner::getDefaultPermissionArg);

    @Override
    public String getDefaultPermissionArg(String permission)
    { return dPArgCache.get(permission); }
    //endregion

    //region userHasGroup(ID userId, String groupName)
    private final BiCache<ID, String, Boolean> uHasGroupCache = new BiCache<>(inner::userHasGroup);

    @Override
    public boolean userHasGroup(ID userId, String groupName)
    { return uHasGroupCache.get(userId, groupName); }
    //endregion

    //region groupExtendsFromGroup(String groupId, String superGroupName)
    private final BiCache<String, String, Boolean> gHasGroupCache = new BiCache<>(inner::groupExtendsFromGroup);

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    { return gHasGroupCache.get(groupId, superGroupName); }
    //endregion

    //region isDefaultGroup(String groupId)
    private final Cache<String, Boolean> dHasGroupCache = new Cache<>(inner::isDefaultGroup);

    @Override
    public boolean isDefaultGroup(String groupId)
    { return dHasGroupCache.get(groupId); }
    //endregion

    //region userHasAllGroups(ID userId, Iterable<String> groupNames)
    private final BiCache<ID, Iterable<String>, Boolean> uHasAllGroupsCache = new BiCache<>(inner::userHasAllGroups);

    @Override
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    { return uHasAllGroupsCache.get(userId, groupNames); }

    @Override
    public boolean userHasAllGroups(ID userId, String... groupNames)
    { return userHasAllGroups(userId, Arrays.asList(groupNames)); }
    //endregion

    //region groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    private final BiCache<String, Iterable<String>, Boolean> gHasAllGroupsCache = new BiCache<>(inner::groupExtendsFromAllGroups);

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    { return gHasAllGroupsCache.get(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    { return groupExtendsFromAllGroups(groupName, Arrays.asList(superGroupNames)); }
    //endregion

    //region areAllDefaultGroups(Iterable<String> groupNames)
    private final Cache<Iterable<String>, Boolean> dHasAllGroupsCache = new Cache<>(inner::areAllDefaultGroups);

    @Override
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    { return dHasAllGroupsCache.get(groupNames); }

    @Override
    public boolean areAllDefaultGroups(String... groupNames)
    { return areAllDefaultGroups(Arrays.asList(groupNames)); }
    //endregion

    //region userHasAnyGroups(ID userId, Iterable<String> groupNames)
    private final BiCache<ID, Iterable<String>, Boolean> uHasAnyGroupsCache = new BiCache<>(inner::userHasAnyGroups);

    @Override
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    { return uHasAnyGroupsCache.get(userId, groupNames); }

    @Override
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    { return userHasAnyGroups(userId, Arrays.asList(groupNames)); }
    //endregion

    //region groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    private final BiCache<String, Iterable<String>, Boolean> gHasAnyGroupsCache = new BiCache<>(inner::groupExtendsFromAnyGroups);

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    { return gHasAnyGroupsCache.get(groupName, superGroupNames); }

    @Override
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    { return groupExtendsFromAnyGroups(groupName, Arrays.asList(superGroupNames)); }
    //endregion

    //region anyAreDefaultGroups(Iterable<String> groupNames)
    private final Cache<Iterable<String>, Boolean> dHasAnyGroupsCache = new Cache<>(inner::anyAreDefaultGroups);

    @Override
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    { return dHasAnyGroupsCache.get(groupNames); }

    @Override
    public boolean anyAreDefaultGroups(String... groupNames)
    { return anyAreDefaultGroups(Arrays.asList(groupNames)); }
    //endregion
    //endregion

    //region Mutators
    @Override
    public void absorb(PermissionsRegistry<ID> other)
    {
        super.absorb(other);
        invalidateCache();
    }

    @Override
    public void removeContentsOf(PermissionsRegistry<ID> other)
    {
        super.removeContentsOf(other);
        invalidateCache();
    }

    @Override
    public Permission assignUserPermission(ID userId, String permission)
    {
        Permission result = super.assignUserPermission(userId, permission);
        invalidateCache();
        return result;
    }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    {
        Permission result = super.assignGroupPermission(groupId, permission);
        invalidateCache();
        return result;
    }

    @Override
    public Permission assignDefaultPermission(String permission)
    {
        Permission result = super.assignDefaultPermission(permission);
        invalidateCache();
        return result;
    }

    @Override
    public void assignUserPermissions(ID userId, List<String> permissions)
    {
        super.assignUserPermissions(userId, permissions);
        invalidateCache();
    }

    @Override
    public void assignUserPermissions(ID userId, String[] permissions)
    {
        super.assignUserPermissions(userId, permissions);
        invalidateCache();
    }

    @Override
    public void assignGroupPermissions(String groupName, List<String> permissions)
    {
        super.assignGroupPermissions(groupName, permissions);
        invalidateCache();
    }

    @Override
    public void assignGroupPermissions(String groupName, String[] permissions)
    {
        super.assignGroupPermissions(groupName, permissions);
        invalidateCache();
    }

    @Override
    public void assignDefaultPermissions(List<String> permissions)
    {
        super.assignDefaultPermissions(permissions);
        invalidateCache();
    }

    @Override
    public void assignDefaultPermissions(String[] permissions)
    {
        super.assignDefaultPermissions(permissions);
        invalidateCache();
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        Permission result = super.revokeUserPermission(userId, permission);
        invalidateCache();
        return result;
    }

    @Override
    public Permission revokeGroupPermission(String groupeName, String permission)
    {
        Permission result = super.revokeGroupPermission(groupeName, permission);
        invalidateCache();
        return result;
    }

    @Override
    public Permission revokeDefaultPermission(String permission)
    {
        Permission result = super.revokeDefaultPermission(permission);
        invalidateCache();
        return result;
    }

    @Override
    public void revokeAllUserPermissions(ID userId)
    {
        super.revokeAllUserPermissions(userId);
        invalidateCache();
    }

    @Override
    public void revokeAllGroupPermissions(String groupName)
    {
        super.revokeAllGroupPermissions(groupName);
        invalidateCache();
    }

    @Override
    public void revokeAllDefaultPermissions()
    {
        super.revokeAllDefaultPermissions();
        invalidateCache();
    }

    @Override
    public void assignGroupToUser(ID userId, String groupNameBeingAssigned)
    {
        super.assignGroupToUser(userId, groupNameBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignGroupToGroup(String groupName, String groupNameBeingAssigned)
    {
        super.assignGroupToGroup(groupName, groupNameBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignDefaultGroup(String groupNameBeingAssigned)
    {
        super.assignDefaultGroup(groupNameBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignGroupsToUser(ID userId, List<String> groupNamesBeingAssigned)
    {
        super.assignGroupsToUser(userId, groupNamesBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignGroupsToUser(ID userId, String[] groupNamesBeingAssigned)
    {
        super.assignGroupsToUser(userId, groupNamesBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignGroupsToGroup(String groupName, List<String> groupNamesBeingAssigned)
    {
        super.assignGroupsToGroup(groupName, groupNamesBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignGroupsToGroup(String groupName, String[] groupNamesBeingAssigned)
    {
        super.assignGroupsToGroup(groupName, groupNamesBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignDefaultGroups(List<String> groupNameBeingAssigned)
    {
        super.assignDefaultGroups(groupNameBeingAssigned);
        invalidateCache();
    }

    @Override
    public void assignDefaultGroups(String[] groupNameBeingAssigned)
    {
        super.assignDefaultGroups(groupNameBeingAssigned);
        invalidateCache();
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupNameBeingRevoked)
    {
        boolean result = super.revokeGroupFromUser(userId, groupNameBeingRevoked);
        invalidateCache();
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupName, String groupNameBeingRevoked)
    {
        boolean result = super.revokeGroupFromGroup(groupName, groupNameBeingRevoked);
        invalidateCache();
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupNameBeingRevoked)
    {
        boolean result = super.revokeDefaultGroup(groupNameBeingRevoked);
        invalidateCache();
        return result;
    }

    @Override
    public void revokeAllGroupsFromUser(ID userId)
    {
        super.revokeAllGroupsFromUser(userId);
        invalidateCache();
    }

    @Override
    public void revokeAllGroupsFromGroup(String groupName)
    {
        super.revokeAllGroupsFromGroup(groupName);
        invalidateCache();
    }

    @Override
    public void revokeAllDefaultGroups()
    {
        super.revokeAllDefaultGroups();
        invalidateCache();
    }

    @Override
    public void clear()
    {
        super.clear();
        invalidateCache();
    }

    @Override
    public void clearUsers()
    {
        super.clearUsers();
        invalidateCache();
    }

    @Override
    public void clearUsers(Collection<ID> userIds)
    {
        super.clearUsers(userIds);
        invalidateCache();
    }

    @Override
    public void clearUsers(ID[] userIds)
    {
        super.clearUsers(userIds);
        invalidateCache();
    }

    @Override
    public void clearUser(ID userId)
    {
        super.clearUser(userId);
        invalidateCache();
    }

    @Override
    public void clearGroups()
    {
        super.clearGroups();
        invalidateCache();
    }

    @Override
    public void clearGroups(Collection<String> groupNames)
    {
        super.clearGroups(groupNames);
        invalidateCache();
    }

    @Override
    public void clearGroups(String[] groupNames)
    {
        super.clearGroups(groupNames);
        invalidateCache();
    }

    @Override
    public void clearGroup(String groupName)
    {
        super.clearGroup(groupName);
        invalidateCache();
    }

    @Override
    public void clearDefaults()
    {
        super.clearDefaults();
        invalidateCache();
    }

    @Override
    public void load() throws IOException
    {
        super.load();
        invalidateCache();
    }
    //endregion
    //endregion
    //endregion
}
