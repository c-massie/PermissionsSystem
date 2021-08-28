package scot.massie.lib.permissions;

import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*;

class PermissionSetTest
{
    /*

    Tests assume that set works as expected, except for the tests for set itself

    Where overloads of String, List<String>, and String... exist, only test the List<String> overload. The other two
    overloads point to the List<String> overload, and the String overload should work where splitPath works as expected.

    static string manipulation methods
        splitPath
            empty string
            string with no separators
            string with multiple separators
            string with empty elements
        applyPermissionToPathStringWithoutArg
            permission
            permission negates
        applyPermissionToPathString
            permission, no arg
            permission, single line arg
            permission, multi-line arg
            permission negates, no arg
            permission negates, single-line arg
            permission negates, multi-line arg

    accessors
        tests as a whole
            hasAny
                empty
                has exact permission
                has descendant permission
            isEmpty
                empty
                has exact permission
                has descendant permission
        getters
            getMostRelevantPermission
                empty
                has no relevant permissions
                has permission exactly in descendant tree
                has permission exactly in exact tree
                has permission that covers in descendant tree
                has permission that covers in exact tree
            getPermission
                doesn't need to be tested, covered by getMostRelevantPermission
        test permissions
            hasPermission
                doesn't need to be tested, covered by getMostRelevantPermission
            hasPermissionOrAnyUnder
                empty
                has no permissions under
                has permission exactly as wildcard
                has permission exactly
                has covered permission as wildcard
                has covered permission
                has covering permission as wildcard
                has covering permission
                has covering permission but negated exactly
                has covering permission but negated above
            hasPermissionOrAnyUnderWhere
                empty
                has no permissions under
                has permission exactly as wildcard
                has permission exactly as wildcard but failing predicate
                has permission exactly
                has permission exactly but failing predicate
                has covered permission as wildcard
                has covered permission as wildcard but failing predicate
                has covered permission
                has covered permission but failing predicate
                has covering permission as wildcard
                has covering permission as wildcard but failing predicate
                has covering permission
                has covering permission but failing predicate
                has covering permission but negated exactly
                has covering permission but negated above
            hasPermissionExactly
                simple function, doesn't need to be tested
            negatesPermission
                doesn't need to be tested, covered by getMostRelevantPermission
            negatesPermissionExactly
                simple function, doesn't need to be tested
        conversion to savestrings
            getPermissionsAsStrings
                empty
                single permission, no args
                single permission, single-line arg
                single permission, multi-line arg
                multiple permissions
            toSaveString
                empty
                single permission, no args
                single permission, single-line arg
                single permission, multi-line arg
                multiple permissions

    mutators
        set
            permission
            permission with single-line arg
            permission with multi-line arg
            wildcard permission
            negating permission
            permission with wildcard in illegal place
            permission with negation in illegal place
        setWhileDeIndenting
            permission without arg
            permission with single-line arg
            permission with multi-line arg
        remove
            empty
            no matching permission
            matching permission
            matching permission, but wrong state of negation
            matching permission, but wrong use of wildcard
            matching permission, also has same permission wildcarded that should not be removed
        clear
            simple function, doesn't need to be tested

     */

    @Test
    void splitPath_empty()
    { assertThat(PermissionSet.splitPath("")).containsExactly(""); }

    @Test
    void splitPath_single()
    { assertThat(PermissionSet.splitPath("first")).containsExactly("first"); }

    @Test
    void splitPath_multi()
    { assertThat(PermissionSet.splitPath("first.second.third")).containsExactly("first", "second", "third"); }

    @Test
    void splitPath_multi_withEmpties()
    { assertThat(PermissionSet.splitPath(".second..fourth.")).containsExactly("", "second", "", "fourth", ""); }

    @Test
    void applyPermissionToPathStringWithoutArg_permits()
    {
        assertThat(PermissionSet.applyPermissionToPathStringWithoutArg("first.second.third",
                                                                       Permission.PERMITTING.withArg("doot")))
                .isEqualTo("first.second.third");
    }

    @Test
    void applyPermissionToPathStringWithoutArg_negates()
    {
        assertThat(PermissionSet.applyPermissionToPathStringWithoutArg("first.second.third",
                                                                       Permission.NEGATING.withArg("doot")))
                .isEqualTo("-first.second.third");
    }

    @Test
    void applyPermissionToPathString_permits_noArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third", Permission.PERMITTING))
                .isEqualTo("first.second.third");
    }

    @Test
    void applyPermissionToPathString_permits_singleLineArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third",
                                                             Permission.PERMITTING.withArg("doot")))
                .isEqualTo("first.second.third: doot");
    }

    @Test
    void applyPermissionToPathString_permits_multiLineArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third",
                                                             Permission.PERMITTING.withArg("doot\nnoot")))
                .isEqualTo("first.second.third:\n    doot\n    noot");
    }

    @Test
    void applyPermissionToPathString_negates_noArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third", Permission.NEGATING))
                .isEqualTo("-first.second.third");
    }

    @Test
    void applyPermissionToPathString_negates_singleLineArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third",
                                                             Permission.NEGATING.withArg("doot")))
                .isEqualTo("-first.second.third: doot");
    }

    @Test
    void applyPermissionToPathString_negates_multiLineArg()
    {
        assertThat(PermissionSet.applyPermissionToPathString("first.second.third",
                                                             Permission.NEGATING.withArg("doot\nnoot")))
                .isEqualTo("-first.second.third:\n    doot\n    noot");
    }

    @Test
    void hasAny_empty()
    { assertThat(new PermissionSet().hasAny()).isFalse(); }

    @Test
    void hasAny_exact() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third");
        assertThat(pset.hasAny()).isTrue();
    }

    @Test
    void hasAny_descendant() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third.*");
        assertThat(pset.hasAny()).isTrue();
    }

    @Test
    void isEmpty_empty()
    { assertThat(new PermissionSet().isEmpty()).isTrue(); }

    @Test
    void isEmpty_exact() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third");
        assertThat(pset.isEmpty()).isFalse();
    }

    @Test
    void isEmpty_descendant() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third.*");
        assertThat(pset.isEmpty()).isFalse();
    }

    @Test
    void getMostRelevantPermission_empty()
    { assertThat(new PermissionSet().getMostRelevantPermission("first", "second")).isNull(); }

    @Test
    void getMostRelevantPermission_hasNoRelevant() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("uno.dos");
        assertThat(pset.getMostRelevantPermission("first", "second")).isNull();
    }

    @Test
    void getMostRelevantPermission_hasExactAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*");
        assertThat(pset.getMostRelevantPermission("first", "second")).isNull();
    }

    @Test
    void getMostRelevantPermission_hasExact() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        PermissionSet.PermissionWithPath pwp = pset.getMostRelevantPermission("first", "second");
        assertThat(pwp).isNotNull();
        assertThat(pwp.getPath()).isEqualTo(Arrays.asList("first", "second"));
        assertThat(pwp.getPermission().permits()).isTrue();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void getMostRelevantPermission_hasCoveringWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*: doot");
        PermissionSet.PermissionWithPath pwp = pset.getMostRelevantPermission("first", "second", "third");
        assertThat(pwp).isNotNull();
        assertThat(pwp.getPath()).isEqualTo(Arrays.asList("first", "second"));
        assertThat(pwp.getPermission().permits()).isTrue();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void getMostRelevantPermission_hasCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        PermissionSet.PermissionWithPath pwp = pset.getMostRelevantPermission("first", "second", "third");
        assertThat(pwp).isNotNull();
        assertThat(pwp.getPath()).isEqualTo(Arrays.asList("first", "second"));
        assertThat(pwp.getPermission().permits()).isTrue();
        assertThat(pwp.getPermission().getArg()).isEqualTo("doot");
    }

    @Test
    void hasPermissionOrAnyUnder_empty()
    { assertThat(new PermissionSet().hasPermissionOrAnyUnder("first.second")).isFalse(); }

    @Test
    void hasPermissionOrAnyUnder_nothingUnder() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("uno.dos: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnder_hasExactlyAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCoveredAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third.*: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCoveringAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.*: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCoveringButNegatedExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        pset.set("-first.second");
        assertThat(pset.hasPermissionOrAnyUnder("first.second")).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnder_hasCoveringButNegatedAbove() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        pset.set("-first.second");
        assertThat(pset.hasPermissionOrAnyUnder("first.second.third")).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_empty()
    { assertThat(new PermissionSet().hasPermissionOrAnyUnderWhere("first.second", x -> true)).isFalse(); }

    @Test
    void hasPermissionOrAnyUnderWhere_nothingUnder() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("uno.dos: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasExactlyAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasExactlyAsWildcard_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasExactly_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveredAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveredAsWildcard_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCovered_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveringAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveringAsWildcard_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.*: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isTrue();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCovering_failingPredicate() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> false)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveringButNegatedExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        pset.set("-first.second");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second", x -> true)).isFalse();
    }

    @Test
    void hasPermissionOrAnyUnderWhere_hasCoveringButNegatedAbove() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first: doot");
        pset.set("-first.second");
        assertThat(pset.hasPermissionOrAnyUnderWhere("first.second.third", x -> true)).isFalse();
    }

    @Test
    void getPermissionsAsStrings_empty()
    { assertThat(new PermissionSet().getPermissionsAsStrings(true)).isEmpty(); }

    @Test
    void getPermissionsAsStrings_single_noArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.getPermissionsAsStrings(true)).containsExactly("first.second");
        assertThat(pset.getPermissionsAsStrings(false)).containsExactly("first.second");
    }

    @Test
    void getPermissionsAsStrings_single_singleLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.getPermissionsAsStrings(true)).containsExactly("first.second: doot");
        assertThat(pset.getPermissionsAsStrings(false)).containsExactly("first.second");
    }

    @Test
    void getPermissionsAsStrings_single_multiLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot\nnoot");
        assertThat(pset.getPermissionsAsStrings(true)).containsExactly("first.second:\n    doot\n    noot");
        assertThat(pset.getPermissionsAsStrings(false)).containsExactly("first.second");
    }

    @Test
    void getPermissionsAsStrings_multiple() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        pset.set("uno.dos.*: doot\nnoot");
        pset.set("-one.two");
        pset.set("ein.zwei: hoot");

        assertThat(pset.getPermissionsAsStrings(true)).containsExactly("ein.zwei: hoot",
                                                                       "first.second",
                                                                       "-one.two",
                                                                       "uno.dos.*:\n    doot\n    noot");

        assertThat(pset.getPermissionsAsStrings(false)).containsExactly("ein.zwei",
                                                                        "first.second",
                                                                        "-one.two",
                                                                        "uno.dos.*");
    }




    @Test
    void toSaveString_empty()
    { assertThat(new PermissionSet().toSaveString()).isEqualTo(""); }

    @Test
    void toSaveString_single_noArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.toSaveString()).isEqualTo("first.second");
    }

    @Test
    void toSaveString_single_singleLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.toSaveString()).isEqualTo("first.second: doot");
    }

    @Test
    void toSaveString_single_multiLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot\nnoot");
        assertThat(pset.toSaveString()).isEqualTo("first.second:\n    doot\n    noot");
    }

    @Test
    void toSaveString_multiple() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        pset.set("uno.dos.*: doot\nnoot");
        pset.set("-one.two");
        pset.set("ein.zwei: hoot");

        assertThat(pset.toSaveString()).isEqualTo(  "ein.zwei: hoot\n"
                                                  + "first.second\n"
                                                  + "-one.two\n"
                                                  + "uno.dos.*:\n    doot\n    noot");
    }
}