package scot.massie.lib.permissions;

import org.junit.jupiter.api.Test;
import scot.massie.lib.collections.trees.Tree;
import scot.massie.lib.collections.trees.TreeEntry;
import scot.massie.lib.functionalinterfaces.Condition;

import java.text.ParseException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

class PermissionSetTest
{
    // Test notes:
    /*
    Tests assume that set works as expected, except for the tests for set itself

    set(...) tests are written against the implementation of PermissionSet. In particular, with the expectation that
    .set(...) will place the correct Permission objects at the correct paths in .exactPermissionTree and
    .descendantPermissionTree.

    Other mutator tests are written assuming the accessors are working as expected.

    Where overloads of String, List<String>, and String... exist, only test the List<String> overload. The other two
    overloads point to the List<String> overload, and the String overload should work where splitPath works as expected.

    */

    //region Methods
    //region Static utils
    //region String manipulation
    //region splitPath(...)
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
    //endregion

    //region applyPermissionToPathStringWithoutArgs(...)
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
    //endregion

    //region applyPermissionToPathString(...)
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
    //endregion
    //endregion
    //endregion

    //region Accessors
    //region Tests as a whole
    //region hasAny()
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

    //endregion

    //region isEmpty(...)
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
    //endregion
    //endregion

    //region Getters
    //region getMostRelevantPermission(...)
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
    //endregion

    //region getPermission(...)

    // Should be covered by getMostRelevantPermission(...) tests.

    //endregion
    //endregion

    //region Check permissions
    //region has permission
    //region has permission normally
    //region hasPermission(...)

    // hasPermission should be covered by getMostRelevantPermission(...) tests. Just some quick sanity tests:
    @Test
    void hasPermission_has() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.hasPermission("first.second")).isTrue();
    }

    @Test
    void hasPermission_hasCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.hasPermission("first.second.third")).isTrue();
    }

    @Test
    void hasPermission_doesntHave()
    {
        PermissionSet pset = new PermissionSet();
        assertThat(pset.hasPermission("first.second")).isFalse();
    }
    //endregion
    //endregion

    //region has permission or any under
    //region hasPermissionOrAnyUnder(...)
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
    //endregion

    //region hasPermissionOrAnyUnderWhere(...)
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
    //endregion
    //endregion

    //region has permission exactly
    @Test
    void hasPermissionExactly_doesntHave()
    {
        PermissionSet pset = new PermissionSet();
        assertThat(pset.hasPermissionExactly("first.second")).isFalse();
    }

    @Test
    void hasPermissionExactly_hasExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.hasPermissionExactly("first.second")).isTrue();
    }

    @Test
    void hasPermissionExactly_hasWildcardExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*");
        assertThat(pset.hasPermissionExactly("first.second.*")).isTrue();
    }

    @Test
    void hasPermissionExactly_doesntHaveExactlyButHasAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*");
        assertThat(pset.hasPermissionExactly("first.second")).isFalse();
    }

    @Test
    void hasPermissionExactly_doesntHaveWildcardExactlyButHasAsNonWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.hasPermissionExactly("first.second.*")).isFalse();
    }

    @Test
    void hasPermissionExactly_doesntHaveButHasCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first");
        assertThat(pset.hasPermissionExactly("first.second")).isFalse();
    }

    @Test
    void hasPermissionExactly_doesntHaveButHasCoveringWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.*");
        assertThat(pset.hasPermissionExactly("first.second")).isFalse();
    }

    @Test
    void hasPermissionExactly_doesntHaveButHasCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third");
        assertThat(pset.hasPermissionExactly("first.second")).isFalse();
    }

    @Test
    void hasPermissionExactly_doesntHaveWildcardButHasCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.third");
        assertThat(pset.hasPermissionExactly("first.*")).isFalse();
        assertThat(pset.hasPermissionExactly("first.second.*")).isFalse();
    }
    //endregion
    //endregion

    //region negates permission
    //region negates permission normally
    //region negatesPermission(...)

    // negatesPermission should be covered by getMostRelevantPermission(...) tests. Just some quick sanity tests:

    @Test
    void negatesPermission_negates() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");
        assertThat(pset.negatesPermission("first.second")).isTrue();
    }

    @Test
    void negatesPermission_negatesCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");
        assertThat(pset.negatesPermission("first.second.third")).isTrue();
    }

    @Test
    void negatesPermission_doesntNegate()
    {
        PermissionSet pset = new PermissionSet();
        assertThat(pset.negatesPermission("first.second")).isFalse();
    }

    //endregion
    //endregion

    //region negates permission exactly
    //region negatesPermissionExactly(...)
    @Test
    void negatesPermissionExactly_doesntNegate()
    {
        PermissionSet pset = new PermissionSet();
        assertThat(pset.negatesPermissionExactly("first.second")).isFalse();
    }

    @Test
    void negatesPermissionExactly_negatesExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");
        assertThat(pset.negatesPermissionExactly("first.second")).isTrue();
    }

    @Test
    void negatesPermissionExactly_negatesWildcardExactly() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second.*");
        assertThat(pset.negatesPermissionExactly("first.second.*")).isTrue();
    }

    @Test
    void negatesPermissionExactly_doesntNegateExactlyButNegatesAsWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second.*");
        assertThat(pset.negatesPermissionExactly("first.second")).isFalse();
    }

    @Test
    void negatesPermissionExactly_doesntNegateWildcardExactlyButNegatesAsNonWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");
        assertThat(pset.negatesPermissionExactly("first.second.*")).isFalse();
    }

    @Test
    void negatesPermissionExactly_doesntNegateButNegatesCovering() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first");
        assertThat(pset.negatesPermissionExactly("first.second")).isFalse();
    }

    @Test
    void negatesPermissionExactly_doesntNegateButNegatesCoveringWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.*");
        assertThat(pset.negatesPermissionExactly("first.second")).isFalse();
    }

    @Test
    void negatesPermissionExactly_doesntNegateButNegatesCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second.third");
        assertThat(pset.negatesPermissionExactly("first.second")).isFalse();
    }

    @Test
    void negatesPermissionExactly_doesntNegateWildcardButNegatesCovered() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second.third");
        assertThat(pset.negatesPermissionExactly("first.*")).isFalse();
        assertThat(pset.negatesPermissionExactly("first.second.*")).isFalse();
    }
    //endregion
    //endregion
    //endregion
    //endregion

    //region Conversion to strings
    //region getPermissionsAsStrings(...)
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
    //endregion

    //region toSaveString(...)
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
    //endregion
    //endregion
    //endregion

    //region Mutators
    //region set
    //region set(...)
    @Test
    void set_permission() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.PERMITTING;
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();

        assertThat(actualExactEntry).isNotNull();

        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING_INDIRECTLY;
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_permissionWithSingleLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.PERMITTING.withArg("doot");
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();
        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING_INDIRECTLY.withArg("doot");
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_permissionWithMultiLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second:\n    doot\n    noot");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.PERMITTING.withArg("doot\n    noot");
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();
        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING_INDIRECTLY.withArg("doot\n    noot");
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_permissionWithMultiLineArg_noNewlineBefore() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot\n    noot");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.PERMITTING.withArg("doot\n    noot");
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();
        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING_INDIRECTLY.withArg("doot\n    noot");
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_permissionWithMultiLineArg_notIndented() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second:\ndoot\nnoot");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.PERMITTING.withArg("doot\nnoot");
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();
        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING_INDIRECTLY.withArg("doot\nnoot");
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_wildcardPermission() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        assertThat(exacts).isEmpty();

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.PERMITTING;
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_negatingPermission() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");

        Tree<String, Permission> exacts = pset.exactPermissionTree;
        Permission expectedExact = Permission.NEGATING;
        assertThat(exacts).hasSize(1);
        TreeEntry<String, Permission> actualExactEntry = exacts.iterator().next();
        assertThat(actualExactEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualExactEntry.getItem()).isEqualTo(expectedExact);

        Tree<String, Permission> descendants = pset.descendantPermissionTree;
        Permission expectedDescendant = Permission.NEGATING_INDIRECTLY;
        assertThat(descendants).hasSize(1);
        TreeEntry<String, Permission> actualDescendantEntry = descendants.iterator().next();
        assertThat(actualDescendantEntry.getPath().getNodes()).containsExactly("first", "second");
        assertThat(actualDescendantEntry.getItem()).isEqualTo(expectedDescendant);
    }

    @Test
    void set_illegalWildcard()
    {
        PermissionSet pset = new PermissionSet();
        assertThrows(ParseException.class, () -> pset.set("first.*.second"));
        assertThrows(ParseException.class, () -> pset.set("*.first.second"));
        assertThrows(ParseException.class, () -> pset.set("first*.second"));
        assertThrows(ParseException.class, () -> pset.set("first.second*"));
        assertThrows(ParseException.class, () -> pset.set("first.second.*.*"));
    }

    @Test
    void set_illegalNegation()
    {
        PermissionSet pset = new PermissionSet();
        assertThrows(ParseException.class, () -> pset.set("first-second"));
        assertThrows(ParseException.class, () -> pset.set("first.-second"));
        assertThrows(ParseException.class, () -> pset.set("first-.second"));
        assertThrows(ParseException.class, () -> pset.set("first.second-"));
        assertThrows(ParseException.class, () -> pset.set("--first-second"));
    }
    //endregion

    //region setWhileDeIndenting(...)
    @Test
    void setWhileDeIndenting_withoutArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.setWhileDeIndenting("first.second");
        Permission perm = pset.getPermission("first.second");

        assertThat(perm.permits()).isTrue();
        assertThat(perm.hasArg()).isFalse();
    }

    @Test
    void setWhileDeIndenting_withSingleLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.setWhileDeIndenting("first.second: doot");
        Permission perm = pset.getPermission("first.second");

        assertThat(perm.permits()).isTrue();
        assertThat(perm.hasArg()).isTrue();
        assertThat(perm.getArg()).isEqualTo("doot");
    }

    @Test
    void setWhileDeIndenting_withSingleLineArgOnNextLine() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.setWhileDeIndenting("first.second:\n    doot");
        Permission perm = pset.getPermission("first.second");

        assertThat(perm.permits()).isTrue();
        assertThat(perm.hasArg()).isTrue();
        assertThat(perm.getArg()).isEqualTo("doot");
    }

    @Test
    void setWhileDeIndenting_withMultiLineArg() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.setWhileDeIndenting("first.second:\n    doot\n    hoot\n    noot");
        Permission perm = pset.getPermission("first.second");

        assertThat(perm.permits()).isTrue();
        assertThat(perm.hasArg()).isTrue();
        assertThat(perm.getArg()).isEqualTo("doot\nhoot\nnoot");
    }
    //endregion

    //region createPermissionFromString(...)

    //endregion

    //region storePermission(...)

    //endregion
    //endregion

    //region remove
    //region remove(...)
    @Test
    void remove_empty()
    {
        PermissionSet pset = new PermissionSet();
        assertThat(pset.remove("first.second")).isNull();
    }

    @Test
    void remove_noMatchingPermission() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("beep.boop");
        assertThat(pset.remove("first.second")).isNull();
        assertThat(pset.getPermission("first.second")).isNull();
        assertThat(pset.getPermission("beep.boop")).isEqualTo(Permission.PERMITTING);
    }

    @Test
    void remove_matchingPermission() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.remove("first.second")).isEqualTo(Permission.PERMITTING);
        assertThat(pset.getPermission("first.second")).isNull();
    }

    @Test
    void remove_matchingPermission_matchingIsNegating() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("-first.second");
        assertThat(pset.remove("first.second")).isEqualTo(Permission.NEGATING);
        assertThat(pset.getPermission("first.second")).isNull();
    }

    @Test
    void remove_matchingPermission_matchingHasArgument() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        assertThat(pset.remove("first.second")).isEqualTo(Permission.PERMITTING.withArg("doot"));
        assertThat(pset.getPermission("first.second")).isNull();
    }

    @Test
    void remove_hasWildcardAndIsWildcarded() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second.*");
        assertThat(pset.remove("first.second.*")).isEqualTo(Permission.PERMITTING);
        assertThat(pset.getPermission("first.second.third")).isNull();
    }

    @Test
    void remove_wrongWildcard() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        pset.set("beep.boop.*");
        assertThat(pset.remove("first.second.*")).isNull();
        assertThat(pset.remove("beep.boop")).isNull();
        assertThat(pset.getPermission("first.second")).isEqualTo(Permission.PERMITTING);
        assertThat(pset.getPermission("beep.boop.*")).isEqualTo(Permission.PERMITTING);
    }

    @Test
    void remove_hasWildcardedAndNotWildcarded() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second: doot");
        pset.set("first.second.*: noot");
        assertThat(pset.remove("first.second")).isEqualTo(Permission.PERMITTING.withArg("doot"));
        assertThat(pset.getPermission("first.second")).isNull();
        assertThat(pset.getPermission("first.second.third")).isEqualTo(Permission.PERMITTING.withArg("noot"));
    }

    @Test
    void remove_inputPermIsNegated_doesntMatter() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.remove("-first.second")).isEqualTo(Permission.PERMITTING);
        assertThat(pset.getPermission("first.second")).isNull();
    }

    @Test
    void remove_inputPermHasArgument_doesntMatter() throws ParseException
    {
        PermissionSet pset = new PermissionSet();
        pset.set("first.second");
        assertThat(pset.remove("first.second: doot")).isEqualTo(Permission.PERMITTING);
        assertThat(pset.getPermission("first.second")).isNull();
    }
    //endregion
    //endregion

    //region clear
    //region clear(...)

    //endregion
    //endregion
    //endregion
    //endregion
}