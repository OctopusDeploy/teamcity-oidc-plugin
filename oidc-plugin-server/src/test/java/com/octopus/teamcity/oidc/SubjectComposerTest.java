package com.octopus.teamcity.oidc;

import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectComposerTest {

    private static final OidcConnection CONNECTION = new OidcConnection("conn1", "project3", "Octopus",
            new IssuanceSettings("api://octopus", 10, "RS256", Set.of()), "jwt.token");

    @Test
    void projectAndBuildTypeAreAlwaysPresent() {
        assertThat(SubjectComposer.compose(Set.of(), Optional.empty(), "project7", "bt42", "", "vcsTrigger"))
                .isEqualTo("project:project7:build_type:bt42");
    }

    @Test
    void connectionPrefixComesFirstWhenDimensionIsSet() {
        assertThat(SubjectComposer.compose(Set.of("connection"), Optional.of(CONNECTION), "project7", "bt42", "", "user"))
                .isEqualTo("connection_project:project3:connection:conn1:project:project7:build_type:bt42");
    }

    @Test
    void connectionPrefixIsOmittedWithoutAConnection() {
        assertThat(SubjectComposer.compose(Set.of("connection"), Optional.empty(), "project7", "bt42", "", "user"))
                .isEqualTo("project:project7:build_type:bt42");
    }

    @Test
    void buildTypeSegmentIsOmittedWhenThereIsNoBuildType() {
        assertThat(SubjectComposer.compose(Set.of("connection"), Optional.of(CONNECTION), "project7", null, "", "user"))
                .isEqualTo("connection_project:project3:connection:conn1:project:project7");
    }

    @Test
    void branchThenTriggerTypeAreAppendedWhenConfigured() {
        assertThat(SubjectComposer.compose(Set.of("branch", "trigger_type"), Optional.empty(), "project7", "bt42", "main", "user"))
                .isEqualTo("project:project7:build_type:bt42:branch:main:trigger_type:user");
    }

    @Test
    void emptyBranchIsOmitted() {
        assertThat(SubjectComposer.compose(Set.of("branch"), Optional.empty(), "project7", "bt42", "", "user"))
                .isEqualTo("project:project7:build_type:bt42");
    }
}
