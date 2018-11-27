handle SIG35 pass nostop noprint

set $CO_ZOMBIE=0
set $CO_IDLE=1
set $CO_READY=2
set $CO_RUNNING=3
set $CO_WAITING=4
set $CO_MIGRATED=5
set $CO_BACKTRACE=0x10

define co_list
  if $argc == 0
    set $END=&proc.co_list.list
  else
    set $END=&((struct pcs_process*)$arg0).co_list.list
  end
  set $CO=(struct pcs_coroutine*)$END.next
  while $CO != $END
    set $STATE=$CO.state.val & ~$CO_BACKTRACE
    if $STATE != $CO_ZOMBIE && $STATE != $CO_IDLE
      set $NAME=$CO.name
      if $NAME == 0
        printf "%p %#x\n", $CO, $STATE
      else
        printf "%p %#x %s\n", $CO, $STATE, $NAME
      end
    end
    set $CO=(struct pcs_coroutine*)$CO.list.next
  end
end

document co_list
Argument: [ "proc" ]
If argument is absent variable "proc" from current frame is used.

Print list of coroutines
end

define co_set
  set $CO=(struct pcs_coroutine*)$arg0
  set $STATE=$CO.state.val & ~$CO_BACKTRACE
  if $STATE == $CO_READY || $STATE == $CO_WAITING
    select-frame 0
    set $CO_SET_SAVED_RBX=$rbx
    set $CO_SET_SAVED_R12=$r12
    set $CO_SET_SAVED_R13=$r13
    set $CO_SET_SAVED_R14=$r14
    set $CO_SET_SAVED_R15=$r15
    set $CO_SET_SAVED_RBP=$rbp
    set $CO_SET_SAVED_PC=$pc
    set $CO_SET_SAVED_SP=$sp
    set $UCONTEXT=(void**)$CO.context.sp
    set $rbx=$UCONTEXT[0]
    set $r12=$UCONTEXT[1]
    set $r13=$UCONTEXT[2]
    set $r14=$UCONTEXT[3]
    set $r15=$UCONTEXT[4]
    set $rbp=$UCONTEXT[5]
    set $pc=$UCONTEXT[6]
    set $sp=$UCONTEXT+7
  else
    printf "Unable to select coroutine %p (state %#x)\n", $CO, $STATE
  end
end

document co_set
Argument: "coroutine address"
Switch gdb context to coroutine. Return to normal context with co_reset.
Do not use co_set twice, yoy will lose original context
end

define co_reset
  select-frame 0
  set $rbx=$CO_SET_SAVED_RBX
  set $r12=$CO_SET_SAVED_R12
  set $r13=$CO_SET_SAVED_R13
  set $r14=$CO_SET_SAVED_R14
  set $r15=$CO_SET_SAVED_R15
  set $rbp=$CO_SET_SAVED_RBP
  set $pc=$CO_SET_SAVED_PC
  set $sp=$CO_SET_SAVED_SP
end

document co_reset
Switch gdb context back to normal after co_reset
end

define co_bt
  if $argc == 0
    set $END=&proc.co_list.list
  else
    set $END=&((struct pcs_process*)$arg0).co_list.list
  end
  set $CO=(struct pcs_coroutine*)$END.next
  select-frame 0
  set $CO_SET_SAVED_RBX=$rbx
  set $CO_SET_SAVED_R12=$r12
  set $CO_SET_SAVED_R13=$r13
  set $CO_SET_SAVED_R14=$r14
  set $CO_SET_SAVED_R15=$r15
  set $CO_SET_SAVED_RBP=$rbp
  set $CO_SET_SAVED_PC=$pc
  set $CO_SET_SAVED_SP=$sp
  while $CO != $END
    set $STATE=$CO.state.val & ~$CO_BACKTRACE
    if $STATE != $CO_ZOMBIE && $STATE != $CO_IDLE
      set $NAME=$CO.name
      if $NAME == 0
        printf "\n%p %#x\n", $CO, $STATE
      else
        printf "\n%p %#x %s\n", $CO, $STATE, $NAME
      end
      if $STATE == $CO_READY || $STATE == $CO_WAITING
        set $UCONTEXT=(void**)$CO.context.sp
        set $rbx=$UCONTEXT[0]
        set $r12=$UCONTEXT[1]
        set $r13=$UCONTEXT[2]
        set $r14=$UCONTEXT[3]
        set $r15=$UCONTEXT[4]
        set $rbp=$UCONTEXT[5]
        set $pc=$UCONTEXT[6]
        set $sp=$UCONTEXT+7
        bt
      else
        printf "Coroutine is running\n"
      end
    end
    set $CO=(struct pcs_coroutine*)$CO.list.next
  end
  set $rbx=$CO_SET_SAVED_RBX
  set $r12=$CO_SET_SAVED_R12
  set $r13=$CO_SET_SAVED_R13
  set $r14=$CO_SET_SAVED_R14
  set $r15=$CO_SET_SAVED_R15
  set $rbp=$CO_SET_SAVED_RBP
  set $pc=$CO_SET_SAVED_PC
  set $sp=$CO_SET_SAVED_SP
end

document co_bt
Argument: [ "proc" ]
If no argument is given "proc" is taken from current context.

Dumps backtraces of all coroutines.
end
