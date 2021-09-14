package scot.massie.lib.permissions;

import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

public class PermissionGroupTest
{
    /*

    As permission groups are built around permission sets, primarily adding fallthrough permissions checking, the
    functionality tested by PermissionSetTest shouldn't need to be tested specifically.

    accessors
        getMostRelevantPermission
            permission that group has
            permission that group has and fallback group does
            permission that group has and default group has
            permission that group doesn't have, that fallback group does
            permission that group doesn't have, that default permissions group does
            permission that group doesn't have that fallback group and default group does
            permission that group doesn't have
        toSaveString
            empty
            single permission
            multiple permissions
            single group
            multiple groups
            single group and permission
    mutators
        addPermissionGroup
            when empty
            when priority in middle of permission group priorities (ensure order)
        removePermissionGroup
            empty
            permission group not present
            permission group present (ensure callback is removed)
        clear
            empty
            permission groups present (ensure callbacks removed)
        reassignPriority
            to same
            to different (ensure group has new priority)
            to different (ensure group is in correct place in order of group that references this one and others)
     */

    PermissionGroup getGroupWithPerms(String[] perms)
    { return getGroupWithPerms("testpermgroup", perms); }

    PermissionGroup getGroupWithPerms(String groupName, String[] perms)
    {
        return new PermissionGroup(groupName)
        {{
            for(String s : perms)
            {
                try
                { permissionSet.set(s); }
                catch(ParseException e)
                { throw new RuntimeException(e); }
            }
        }};
    }

    PermissionGroup getGroupWithPermsAndFallback(String[] perms, PermissionGroup fallback)
    { return getGroupWithPermsAndFallback("testpermgroup", perms, fallback); }

    PermissionGroup getGroupWithPermsAndFallback(String groupName, String[] perms, PermissionGroup fallback)
    {
        return new PermissionGroup(groupName)
        {{
            for(String s : perms)
            {
                try
                { permissionSet.set(s); }
                catch(ParseException e)
                { throw new RuntimeException(e); }
            }

            referencedGroups.add(fallback);
        }};
    }

    PermissionGroup getGroupWithPermsAndDefault(String[] perms, PermissionGroup def)
    { return getGroupWithPermsAndDefault("testpermgroup", perms, def); }

    PermissionGroup getGroupWithPermsAndDefault(String groupName, String[] perms, PermissionGroup def)
    {
        return new PermissionGroup(groupName, def)
        {{
            for(String s : perms)
            {
                try
                { permissionSet.set(s); }
                catch(ParseException e)
                { throw new RuntimeException(e); }
            }
        }};
    }

    PermissionGroup getGroupWithPermsFallbackAndDefault(String[] perms, PermissionGroup fallback, PermissionGroup def)
    { return getGroupWithPermsFallbackAndDefault("testpermgroup", perms, fallback, def); }

    PermissionGroup getGroupWithPermsFallbackAndDefault(String groupName,
                                                        String[] perms,
                                                        PermissionGroup fallback,
                                                        PermissionGroup def)
    {
        return new PermissionGroup(groupName, def)
        {{
            for(String s : perms)
            {
                try
                { permissionSet.set(s); }
                catch(ParseException e)
                { throw new RuntimeException(e); }
            }

            referencedGroups.add(fallback);
        }};
    }

    @Test
    void getMostRelevantPermission_has()
    {
        PermissionGroup pg = getGroupWithPerms(new String[] {"first.second.third: doot"});
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void getMostRelevantPermission_hasAndFallbackHas()
    {
        PermissionGroup fbpg = getGroupWithPerms(new String[] {"first.second.third: noot"});
        PermissionGroup pg = getGroupWithPermsAndFallback(new String[] {"first.second.third: doot"}, fbpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void getMostRelevantPermission_hasAndDefaultHas()
    {
        PermissionGroup dpg = getGroupWithPerms(new String[] {"first.second.third: hoot"});
        PermissionGroup pg = getGroupWithPermsAndDefault(new String[] {"first.second.third: doot"}, dpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void getMostRelevantPermission_fallbackHas()
    {
        PermissionGroup fbpg = getGroupWithPerms(new String[] {"first.second.third: noot"});
        PermissionGroup pg = getGroupWithPermsAndFallback(new String[] {}, fbpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("noot");
    }

    @Test
    void getMostRelevantPermission_defaultHas()
    {
        PermissionGroup dpg = getGroupWithPerms(new String[] {"first.second.third: hoot"});
        PermissionGroup pg = getGroupWithPermsAndDefault(new String[] {}, dpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("hoot");
    }

    @Test
    void getMostRelevantPermission_fallbackAndDefaultHas()
    {
        PermissionGroup dpg = getGroupWithPerms(new String[] {"first.second.third: hoot"});
        PermissionGroup fbpg = getGroupWithPerms(new String[] {"first.second.third: noot"});
        PermissionGroup pg = getGroupWithPermsFallbackAndDefault(new String[] {}, fbpg, dpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNotNull();
        assertThat(pwp.getPermission().getArg()).isEqualTo("noot");
    }

    @Test
    void getMostRelevantPermission_doesntHave()
    {
        PermissionGroup dpg = getGroupWithPerms(new String[] {});
        PermissionGroup fbpg = getGroupWithPerms(new String[] {});
        PermissionGroup pg = getGroupWithPermsFallbackAndDefault(new String[] {}, fbpg, dpg);
        PermissionSet.PermissionWithPath pwp = pg.getMostRelevantPermission("first.second.third");

        assertThat(pwp).isNull();
    }
}