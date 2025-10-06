"""Very rough first try extracting state machine structure from the C++ code.

If this is successful, we would ultimately like to use it to draw diagrams
with plant UML.
"""

import os
import re


class Transition:
    """An event that causes a transition to another state.

    possibly subject to a guard.
    """

    def __init__(self, source, events, target, guard=None, action=None):
        """Give up and just making these public for now."""
        self.source = source
        self.events = events  # could be a string or a list/tuple
        self.target = target
        self.guard = guard
        self.action = action

    def events_as_string(self, wrap=None):
        """Get the one or several events as a printable string."""
        if isinstance(self.events, str):
            return self.events
        elif len(self.events) == 1:
            return self.events[0]
        else:
            event_string = "("
            for idx, event in enumerate(self.events):
                event_string += event
                if idx < (len(self.events) - 1):  # there are more to come
                    if (
                        wrap and len(self.events) > wrap
                    ):  # there are too many for a single line
                        event_string += "\\n| "
                    else:
                        event_string += " | "
            event_string += ")"
            return event_string

    def euml_string(self):
        """Describe the transition in eUML syntax."""
        return "{} + {} [{}] / {} == {}".format(
            self.source,
            self.events_as_string(),
            self.guard,
            self.action,
            self.target,
        )


class State:
    """Container to represent a state in the state machine."""

    def __init__(self, name, parent=None):
        """Initialize a new state."""
        self._name = name
        self._parent = parent
        self._children = []
        self._initial_state = None
        self._transitions = []
        self._entry = []
        self._exit = []
        # children are responsible for registering themselves
        # with their parents
        if self._parent:
            self._parent.register_child(self)

    @property
    def name(self):
        """Read-only access to name."""
        return self._name

    @property
    def parent(self):
        """Read-only access to parent."""
        return self._parent

    @property
    def children(self):
        """Read-only access to children."""
        return self._children

    @property
    def entry(self):
        """Entry property."""
        return self._entry

    @property
    def exit(self):
        """Exit property."""
        return self._exit

    @property
    def initial_state(self):
        """Initialize property."""
        return self._initial_state

    @property
    def transitions(self):
        """Transitions property."""
        return self._transitions

    def is_substate_of(self, name):
        """Is substrate of.

        Is this state a substate of some other named state?
        """
        if self.parent.name == name:
            return True
        elif self.parent.name == "Top":
            # Assume there is always a state named 'Top' to end the recursion
            return False
        else:
            # recurse our way up the state hierarchy
            return self.parent.is_substate_of(name)

    def levels_of_nesting_below(self, name):
        """Level of nesting below name.

        How many levels deep is this state nested below the named super-state?
        """
        # print('{}.levels_of_nesting_below({})'.format(self.name, name))
        if self.name == "Top":
            return 0
        elif self.name == name:
            return 0
        elif self.parent.name == name:
            return 1
        elif self.parent.name == "Top":
            return None  # to signify failure
        else:
            # recurse our way up the state hierarchy
            return self.parent.levels_of_nesting_below(name) + 1

    def ancestor_at_most_n_levels_of_nesting_below(self, name, max_depth):
        """Ancestor at most n levels of nesting below.

        Find ancestor that is at most N levels of nesting below named
        super-state.
        """
        assert self.is_substate_of(name)
        if self.levels_of_nesting_below(name) <= max_depth:
            return self
        else:
            return self.parent.ancestor_at_most_n_levels_of_nesting_below(
                name, max_depth
            )

    def register_child(self, child):
        """Register child.

        Children are responsible for registering themselves with the parent
        """
        assert child.parent == self
        self._children.append(child)

    def add_initial_state(self, initial_state):
        """Add initial state.

        Initial state transition for a composite state is represented by
        a dot on the diagram.
        """
        assert initial_state in self._children
        self._initial_state = initial_state

    def add_transition(self, transition):
        """Add transition.

        Transitions are defined by an event, target_state, and guard_condition.
        """
        assert transition.source == self._name
        self._transitions.append(transition)

    def add_entry(self, statement):
        """Add entry.

        For now, we're just going to keep the full block of code
        we found in hsmEntry().
        """
        stripped_statement = statement.strip()
        if stripped_statement[:2] == "//":
            # ignore commented out lines
            return
        if stripped_statement == "":
            # ignore empty lines
            return
        self._entry.append(stripped_statement)

    def add_exit(self, statement):
        """Add exit.

        For now, we're just going to keep the full block of code
        we found in hsmExit().
        """
        stripped_statement = statement.strip()
        if stripped_statement[:2] == "//":
            # ignore commented out lines
            return
        if stripped_statement == "":
            # ignore empty lines
            return
        self._exit.append(stripped_statement)

    def print_state_hierarchy(self, indentation=0):
        """Print state hierarchy."""
        description_of_self = " " * indentation + self._name
        if self._initial_state:
            description_of_self += " ( --> {})".format(
                self._initial_state.name
            )
        print(description_of_self)
        for child in self._children:
            child.print_state_hierarchy(indentation=indentation + 4)

    def print_transition_table(self, indentation=0):
        """Print transition table."""
        for transition in self._transitions:
            print(" " * indentation + transition.euml_string())
        for child in self._children:
            child.print_transition_table(indentation=indentation + 4)


class StateMachine:
    """A collection of states makes a state machine."""

    def __init__(self, basename, path=None, namespace=None):
        """Initialize a new state machine."""
        self._basename = basename
        self._path = path
        self._namespace = namespace
        self._states = {}
        self._plant_uml_legend = []
        self._plant_uml_out_of_scope_transition = False

        self._enum_to_typedef = {}

    @staticmethod
    def find(path, name):
        """Walk directory to find."""
        for root, dirs, files in os.walk(path):
            if name in files:
                return os.path.join(root, name)

    def state(self, name):
        print("states {}".format(self._states))
        """Get a reference to an individual state by name."""
        return self._states[name]

    def add_state(self, state):
        """Add state."""
        self._states[state.name] = state
        # TODO: is there any additional linking we need to do here?
        # TODO: Maybe populate children?

    def _add_legend_entry(self, entry):
        """Add legend entry.

        Legend entries to appear at the bottom of the plantUML diagram.
        """
        if entry in self._plant_uml_legend:
            # already have this one, do not repeat
            return
        else:
            self._plant_uml_legend.append(entry)

    def print_state_hierarchy(self):
        """Print state hierarchy."""
        # Assume that we always have a top state called 'Top'
        print("State hierarchy for {} state machine".format(self._basename))
        self.state("Top").print_state_hierarchy()

    def print_transition_table(self):
        """Print transition table."""
        # Assume that we always have a top state called 'TOP'
        print("Transition table for {} state machine".format(self._basename))
        self.state("Top").print_transition_table()

    def extract_everything(self):
        """Extract everything.

        Scan files in standard locations for all of the things
        we know how to scrape.
        """
        self.extract_state_tree()
        self.extract_initial_states()
        self.extract_transitions()
        self.extract_entry_exit_actions()

    def extract_state_tree(self):
        """Extract state tree.

        Scan a file looking for state declarations.
        """
        header = self.find(self._path, self._basename + ".hpp")
        print("Header {}".format(self._path + self._basename + ".hpp"))
        with open(header, "r") as f:
            raw_lines = [re.sub(r"//.*", "", line).rstrip() for line in f]

        statements, current = [], ""
        for line in raw_lines:
            s = line.strip()
            if not s:
                continue
            if s.startswith("using "):
                current = s
            else:
                current += " " + s
            if s.endswith(";"):
                statements.append(current)
                current = ""

        re_using = re.compile(r'^\s*using\s+(\w+)\s*=\s*(.+);$')
        re_top = re.compile(r'\bTopState<')
        re_comp = re.compile(r'\bCompState<([^,]+),\s*([^>]+)>')
        re_leaf = re.compile(r'\bLeafState<([^,]+),\s*([^>]+)>')
        # pull enum from traits like HapticStateTraits<HapticState::IDLE>
        re_enum = re.compile(r'HapticState::(\w+)')

        for stmt in statements:
            m = re_using.match(stmt)
            if not m:
                continue

            state_name, rhs = m.groups()
            rhs = rhs.strip()

            if re_top.search(rhs):
                self.add_state(State(name=state_name))
                # Top maps from eTop -> Top if it appears elsewhere
                self._enum_to_typedef.setdefault('eTop', state_name)
                continue

            mc = re_comp.search(rhs)
            ml = re_leaf.search(rhs)
            if mc or ml:
                first_arg, parent = (mc or ml).groups()
                parent = parent.strip()
                # Register the child
                self.add_state(State(name=state_name, parent=self.state(parent)))
                # Record enum -> typedef mapping if present
                em = re_enum.search(first_arg)
                if em:
                    self._enum_to_typedef[em.group(1)] = state_name

    def extract_initial_states(self, verbose=False, extension="-hsm.hpp"):
        """Extract initial states.

        Scan a file looking for initial state transitions
        (dots on state diagram).
        """
        header = self.find(self._path, self._basename + extension)
        with open(header, "r") as fid:
            lines = fid.readlines()

        for line in lines:
            if "//" == line.strip()[:2]:
                # ignore commented lines
                continue

            # Fragile: counting on finding these in the right order
            if "::init(" in line:
                # This is the function signature which gives us the superstate
                superstate_name = line.split("::")[1]
                if superstate_name == "detail":
                    superstate_name = line.split("::")[2]
                if verbose:
                    print("superstate = {}".format(superstate_name))
            elif "Init<" in line:
                # this is the line that defines the actual intial transition
                # and gives us the target
                first_part_of_line = line.split()[0]
                target_name = first_part_of_line.split("::")[-1][
                    :-1
                ]  # last chunk, then strip off '>'
                self.state(superstate_name).add_initial_state(
                    self.state(target_name)
                )
                if verbose:
                    print("target = {}".format(target_name))

    def extract_transitions(self, verbose=False, extension="-hsm.hpp"):
        """Extract transitions.

        Scan a file looking for state transitions driven by events.
        """
        header = self.find(self._path, self._basename + extension)
        with open(header, "r") as fid:
            lines = fid.readlines()

        for line in lines:
            if "//" == line.strip()[:2]:
                # ignore commented lines
                continue

            # Fragile: counting on finding these in the right order
            if "::handleEvent({}::".format(self._namespace) in line:
                # This is the function signature which gives
                # us the source state
                source_state_name = line.split("::")[1]
                # we can have multiple events tied to the same
                # transition details, so keep a *list* of "active" events
                # that the details will apply to when we find them.
                event_list = []
                if source_state_name == "detail":
                    source_state_name = line.split("::")[2]
                if verbose:
                    print("source = {}".format(source_state_name))
            elif "case" in line and "::" in line:  # TODO: use regex
                # this is the case label of the switch(event),
                # which gives us the event name
                event_name = line.split(":")[-2]
                event_list.append(event_name)
                # when we hit a new case (event), reset the guard_condition
                guard_condition = ""
                if verbose:
                    print("event = {}".format(event_name))
            elif "return" in line or "break" in line:
                # we have passed the end of a case block
                # (that potentially fell through from a prior `case`)
                event_list = []
            # TODO: look for actions; this might be difficult
            elif "if(" in line or "if (" in line:
                # this is the guard condition
                # for now, just take the entire line
                guard_condition = line.strip()
                if verbose:
                    print("guard = {}".format(guard_condition))
            elif "Transition<Current" in line:
                # this is the transition statement,
                # which gives us the target state name
                target_state_name = line.split("::")[1].split(">")[0]
                if target_state_name.startswith("detail"):
                    target_state_name = line.split("::")[2].split(">")[0]
                # TODO: handling internal/external transition semantics
                #       for now, just strip off the extra words that are
                #       confusing the plot generation
                target_state_name = target_state_name.split(",")[0]
                # If we fell through multiple `case` statements,
                # this transition might apply to multiple events
                # I debated whether this should be considered one
                # transition with multiple events,
                # or multiple similar transitions.
                # In the python representation of the state machine, I would
                # rather these be represented as separate events, but in the
                # plantUml diagram, I would rather them show up as a single
                # arrow (especially by the time there are guards and actions
                #  involved).
                # It seemed like a lot of work to search the model and/or
                # plantUml code for duplicate transitions that could be
                # collapsed, so I decided to just store it as a single
                # multi-event transition from the beginning, but let the
                # plantUml generator deal with stingifying the list of events.
                assert (
                    len(event_list) >= 1
                ), "need to have found at least one event to associate with a transition"  # noqa: E501
                transition = Transition(
                    source=source_state_name,
                    events=event_list,
                    guard=guard_condition,
                    target=target_state_name,
                )
                if verbose:
                    print(transition.euml_string())
                self.state(source_state_name).add_transition(transition)

    def extract_entry_exit_actions(self, verbose=False):
        """Extract entry exit actions.

        Scan a file looking for entry and exit actions.
        """
        header = self.find(self._path, self._basename + "-inl.hpp")
        if header is None:
            if verbose:
                print("No *-inl.hpp file; skipping entry/exit extraction.")
            return

        # Allow optional namespaces like haptic::HapticState::IDLE
        enum_pat = r'(?:\w+::)*HapticState::(?P<state>\w+)'
        entry_re = re.compile(rf'inline\s+void\s+\w+::(?:entry|hsmEntry)\s*<\s*{enum_pat}\s*>\s*\(\s*\)\s*\{{')
        exit_re = re.compile(rf'inline\s+void\s+\w+::(?:exit|hsmExit)\s*<\s*{enum_pat}\s*>\s*\(\s*\)\s*\{{')

        in_entry_function = False
        in_exit_function = False
        state_enum = None

        with open(header, "r") as fid:
            for raw in fid:
                line = raw.rstrip("\n")

                if line.strip().startswith("//"):
                    continue

                if not in_entry_function and not in_exit_function:
                    m = entry_re.search(line)
                    if m:
                        in_entry_function = True
                        state_enum = m.group("state")
                        if verbose:
                            print(f"{state_enum} entry {{")
                        continue

                    m = exit_re.search(line)
                    if m:
                        in_exit_function = True
                        state_enum = m.group("state")
                        if verbose:
                            print(f"{state_enum} exit {{")
                        continue

                if (in_entry_function or in_exit_function) and line.strip() == "}":
                    if verbose:
                        print("}  // closing entry" if in_entry_function else "}  // closing exit")
                    in_entry_function = in_exit_function = False
                    state_enum = None
                    continue

                if in_entry_function:
                    # Translate enum -> typedef name
                    typedef_name = self._enum_to_typedef.get(state_enum, state_enum)
                    self.state(typedef_name).add_entry(line)
                    if verbose:
                        print(f"  entry stmt: {line.strip()}")

                elif in_exit_function:
                    typedef_name = self._enum_to_typedef.get(state_enum, state_enum)
                    self.state(typedef_name).add_exit(line)
                    if verbose:
                        print(f"  exit stmt: {line.strip()}")

    def generate_event_set(self):
        """Generate a set of all events that are USED by the state machine.

        This conceptually could be different than the list of events that are
        DEFINED in the enum.
        """
        events = set()  # unordered and unique
        for name, state in self._states.items():
            for transition in state.transitions:
                events.update(transition.events)
        return events

    def generate_plant_uml(
        self,
        top="Top",
        max_depth=None,
        do_not_expand=None,
        include_actions=True,
        include_guards=True,
        filename=None,
        use_path=False,
    ):
        """Generate plant uml.

        Generate the text input expected by PlantUML for automatically drawing
        a UML state diagram.

        `top` specifies the top of **this** diagram, effectively defining
            the scope
        `do_not_expand` is a LIST of states to not expand into substates
        """
        if use_path:
            filename = os.path.join(self._path, filename)
        if not filename:
            filename = os.path.join(
                self._path, self._basename + "-PlantUML.txt"
            )

        # Clear members that will be populated by the recursive calls
        # to _generate_plant_uml_for_state below
        self._plant_uml_legend = []
        self._plant_uml_out_of_scope_transition = False

        with open(filename, "w") as fid:

            # header
            fid.write("@startuml\n")

            # start with some assumed "top" state and then diagram downward
            # from there
            self._generate_plant_uml_for_state(
                fid,
                state=self.state(top),
                top=top,
                max_depth=max_depth,
                do_not_expand=do_not_expand,
                include_actions=include_actions,
                include_guards=include_guards,
            )

            # If any transition **targets** are out of the current diagram
            # scope, we create a single explicitly named
            # fake-state at the top level for these transitions to point to.
            if self._plant_uml_out_of_scope_transition:
                fid.write("state OutOfScope {\n}\n")

            if self._plant_uml_legend:
                fid.write("legend\n")
                for entry in self._plant_uml_legend:
                    fid.write("  {}\n".format(entry))
                fid.write("end legend\n")

            # footer
            fid.write("@enduml\n")

    def _generate_plant_uml_for_state(
        self,
        fid,
        state,
        top,
        max_depth,
        do_not_expand,
        include_actions,
        include_guards,
        indentation=0,
    ):
        """Generate plant uml for state.

        Generate the text input expected by PlantUML for automatically drawing
        a UML state diagram

        `top` specifies the top of **this** diagram, effectively defining
        the scope.

        Transitions to states outside of this scope will be directed to UML's
        "final" state.

        Transitions from states outside of this scope are (for now) simply
        omitted.

        This functionality original resided within the State class, but I was
        having to pass in a reference to the state machine in order to look up
        "scope" of target states, so I decided to move it here to the
        StateMachine class.  The downside is that now I had to make more of
        the details of the State class public.
        """
        initial_indent = " " * indentation
        internal_indent = " " * (indentation + 2)

        # declare ourselves as a state
        fid.write(initial_indent + "state {} {{\n".format(state.name))

        # describe transition to initial state, if any
        if do_not_expand is not None and state.name in do_not_expand:
            # regardless of how deep we are, we will not descend into our
            # sub-states
            pass
        elif (
            max_depth is None or state.levels_of_nesting_below(top) < max_depth
        ):
            if state.initial_state:
                fid.write(
                    internal_indent
                    + "[*] --> {}\n".format(state.initial_state.name)
                )

        # entry/exit actions
        if include_actions:  # even if at max_depth
            for entry in state.entry:
                fid.write(
                    internal_indent
                    + "{} : entry / {}\n".format(state.name, entry)
                )
            for exit in state.exit:
                fid.write(
                    internal_indent
                    + "{} : exit / {}\n".format(state.name, exit)
                )

        # list transitions
        for transition in state.transitions:
            arrow = "-->"

            # figure out if the target state is hidden by do_not_expand list
            do_not_expand_state_hiding_target = None
            if do_not_expand is not None:
                for name in do_not_expand:
                    if self.state(transition.target).is_substate_of(name):
                        do_not_expand_state_hiding_target = name

            # catch transitions to states that are out of scope for the
            # current diagram
            if not self.state(transition.target).is_substate_of(top):
                # Previously useed UML's "Final" state icon to represent that
                # we have left the current diagram. The problem with this was
                # that it generated a "Final" icon locally in every state that
                # had an out-of-scope transition, which often bloated the
                # diagram.  Instead, we're going to create a single explicit
                # "OutOfScope" state for all of these transitions to point to.
                diagram_target = "OutOfScope"  # '[*]'
                # Flag that this occurred so that generate_plant_uml can
                # create the state at the top level
                self._plant_uml_out_of_scope_transition = True
            elif (
                max_depth is not None
                and state.levels_of_nesting_below(top) == max_depth
                and self.state(transition.target).is_substate_of(state.name)
            ):
                # If the current state is already the max depth, then drop
                # transitions to our own substates (instead of letting the
                # next elif redirect them to ourselves)
                break
            elif do_not_expand is not None and state.name in do_not_expand:
                # If the current state is explicitly not going to be expanded,
                # then drop transitions to our own substates so that they do
                # not get auto-drawn.
                break
            elif (
                max_depth is not None
                and self.state(transition.target).levels_of_nesting_below(top)
                > max_depth
            ):
                # redirect transitions to deeply nested states to their
                # parent state
                diagram_target = (
                    self.state(transition.target)
                    .ancestor_at_most_n_levels_of_nesting_below(top, max_depth)
                    .name
                )
                # use a different style arrow to explicitly show that this has
                # been modified/approximated
                arrow = "-[dotted]->"
                self._add_legend_entry(
                    "dotted arrow = transition to hidden substate"
                )
            elif do_not_expand_state_hiding_target:
                # redirect transitions to states hidden by do_no_expand list
                diagram_target = do_not_expand_state_hiding_target
                # use a different style arrow to explicitly show that this has
                # been modified/approximated
                arrow = "-[dotted]->"
                self._add_legend_entry(
                    "dotted arrow = transition to hidden substate"
                )
            else:  # target in scope
                diagram_target = transition.target

            # start generating the actual plantUML string to represent
            # a transition
            transition_string = "{} {} {} : {}".format(
                transition.source,
                arrow,
                diagram_target,
                transition.events_as_string(wrap=3),
            )
            if transition.guard:
                if include_guards:
                    transition_string += " [{}]".format(transition.guard)
                else:
                    # explicitly show that a guard condition has been omitted
                    transition_string += " [*]"
                    self._add_legend_entry("[*] = guard condition omitted")

            if transition.action:
                if include_actions:
                    transition_string += " / {}".format(transition.action)
                else:
                    # explicitly show that a transition action has been omitted
                    transition_string += " /*"
                    self._add_legend_entry("/* = transition action omitted")

            fid.write(internal_indent + transition_string + "\n")

        # include sub-states
        if do_not_expand is not None and state.name in do_not_expand:
            # regardless of how deep we are, we will not descend into our
            # sub-states
            pass
        elif (
            max_depth is None or state.levels_of_nesting_below(top) < max_depth
        ):
            for child in state.children:
                self._generate_plant_uml_for_state(
                    fid,
                    state=child,
                    top=top,
                    max_depth=max_depth,
                    do_not_expand=do_not_expand,
                    include_actions=include_actions,
                    include_guards=include_guards,
                    indentation=indentation + 2,
                )

        # close our block
        fid.write(initial_indent + "}\n")


if __name__ == "__main__":

    example_control = StateMachine(
        basename="ExampleControl",
        path="../../../cpp/eta/hsm/tests",
        namespace="example_control",
    )
    example_control.extract_everything()

    print()
    example_control.print_state_hierarchy()
    print()
    example_control.print_transition_table()

    # Check state hierarchy
    assert example_control.state("Sober").is_substate_of("Alive")
    assert example_control.state("Sober").is_substate_of("Top")
    assert ~example_control.state("Dead").is_substate_of("Alive")
    assert example_control.state("Dead").is_substate_of("Top")

    # default plantUML output
    example_control.generate_plant_uml(
        filename="testing/ExampleControl-All.txt"
    )

    # Suppress guard conditions on transitions
    example_control.generate_plant_uml(
        filename="testing/ExampleControl-NoGuardsOrActions.txt",
        include_guards=False,
        include_actions=False,
    )

    # Generate selected portions of the state diagram
    example_control.generate_plant_uml(
        filename="testing/ExampleControl-Alive.txt", top="Alive"
    )
    example_control.generate_plant_uml(
        filename="testing/ExampleControl-Dead.txt", top="Dead"
    )

