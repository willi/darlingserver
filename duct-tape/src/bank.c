/*
 * The BANK voucher attribute manager, ported from XNU's osfmk/bank/bank.c.
 *
 * libdispatch creates a BANK voucher in every process and attaches one to every message it sends,
 * so without this manager no XPC client can start ("Could not create task mach voucher").
 *
 * XNU's bank also bills CPU time and energy through ledgers, and carries thread groups and personas.
 * darlingserver has none of those, so this port keeps only the voucher values that userspace can observe:
 * the task holding a voucher, the task that redeemed it (the merchant), and the originator and proximate process.
 * Two deliberate differences from XNU:
 *   - every task has PERSONA_ID_NONE, so persona modification (MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA) is never allowed;
 *   - every task propagates its secure originator, as platform binaries do on XNU. Darling has no code signing,
 *     and its IOTaskHasEntitlement() stub answers TRUE for every entitlement, including the one that forbids propagation.
 *
 * Locking: XNU uses a lock per bank task. A single lock is plenty here; it guards the made counts,
 * the voucher references and the holders' account lists. Element reference counts are atomic, as in XNU.
 */

#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/log.h>

#include <kern/task.h>
#include <bank/bank_internal.h>
#include <mach/mach_voucher_attr_control.h>

#include <stdlib.h>

// from bsd/sys/persona.h, which osfmk code can't include
#define PERSONA_ID_NONE ((uint32_t)-1)

#define BANK_ELEMENT_TO_HANDLE(x) (CAST_DOWN(bank_handle_t, (x)))
#define HANDLE_TO_BANK_ELEMENT(x) (CAST_DOWN(bank_element_t, (x)))

#define CAST_TO_BANK_ELEMENT(x) ((bank_element_t)((void *)(x)))
#define CAST_TO_BANK_TASK(x) ((bank_task_t)((void *)(x)))
#define CAST_TO_BANK_ACCOUNT(x) ((bank_account_t)((void *)(x)))

static lck_mtx_t bank_lock;
static ipc_voucher_attr_control_t bank_voucher_attr_control;

static kern_return_t bank_release_value(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_t value, mach_voucher_attr_value_reference_t sync);
static kern_return_t bank_get_value(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_recipe_command_t command, mach_voucher_attr_value_handle_array_t prev_values,
	mach_msg_type_number_t prev_value_count, mach_voucher_attr_content_t recipe,
	mach_voucher_attr_content_size_t recipe_size, mach_voucher_attr_value_handle_t* out_value,
	mach_voucher_attr_value_flags_t* out_flags, ipc_voucher_t* out_value_voucher);
static kern_return_t bank_extract_content(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_array_t values, mach_msg_type_number_t value_count,
	mach_voucher_attr_recipe_command_t* out_command, mach_voucher_attr_content_t out_recipe,
	mach_voucher_attr_content_size_t* in_out_recipe_size);
static kern_return_t bank_command(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_array_t values, mach_msg_type_number_t value_count,
	mach_voucher_attr_command_t command, mach_voucher_attr_content_t in_content,
	mach_voucher_attr_content_size_t in_content_size, mach_voucher_attr_content_t out_content,
	mach_voucher_attr_content_size_t* out_content_size);
static void bank_release(ipc_voucher_attr_manager_t manager);

static const struct ipc_voucher_attr_manager bank_manager = {
	.ivam_release_value    = bank_release_value,
	.ivam_get_value        = bank_get_value,
	.ivam_extract_content  = bank_extract_content,
	.ivam_command          = bank_command,
	.ivam_release          = bank_release,
	.ivam_flags            = (IVAM_FLAGS_SUPPORT_SEND_PREPROCESS | IVAM_FLAGS_SUPPORT_RECEIVE_POSTPROCESS),
};

void bank_init(void) {
	lck_mtx_init(&bank_lock, LCK_GRP_NULL, LCK_ATTR_NULL);

	kern_return_t kr = ipc_register_well_known_mach_voucher_attr_manager(&bank_manager, 0,
		MACH_VOUCHER_ATTR_KEY_BANK, &bank_voucher_attr_control);
	if (kr != KERN_SUCCESS) {
		panic("BANK subsystem initialization failed");
	}
};

/*
 * Bank tasks and accounts
 */

static void bank_task_dealloc(bank_task_t bank_task, mach_voucher_attr_value_reference_t sync) {
	if (bank_task_release_num(bank_task, sync) > (int)sync) {
		return;
	}

	assert(bank_task->bt_refs == 0);
	assert(queue_empty(&bank_task->bt_accounts_to_pay));
	free(bank_task);
};

static bank_task_t bank_task_alloc_init(task_t task) {
	dtape_task_t* dtask = dtape_task_for_xnu_task(task);
	bank_task_t bank_task = malloc(sizeof(*bank_task));

	if (bank_task == BANK_TASK_NULL) {
		return BANK_TASK_NULL;
	}

	memset(bank_task, 0, sizeof(*bank_task));
	bank_task->bt_type = BANK_TASK;
	bank_task->bt_refs = 1; // the task's reference, dropped by bank_task_destroy()
	bank_task->bt_ledger = LEDGER_NULL;
	bank_task->bt_hasentitlement = TRUE; // see the top of this file
	queue_init(&bank_task->bt_accounts_to_pay);
	queue_init(&bank_task->bt_accounts_to_charge);

	// XNU's p_uniqueid never repeats while the system is up; neither do darlingserver's eternal IDs. The task has its
	// process's by now, except the kernel task, which dtape_task_create() gives it later
	bank_task->bt_unique_pid = dtask->p_ident.eid;
	bank_task->bt_pid = dtask->saved_pid;
	bank_task->bt_pidversion = task->audit_token.val[7];
	bank_task->bt_persona_id = PERSONA_ID_NONE;
	bank_task->bt_uid = task->audit_token.val[1];
	bank_task->bt_gid = task->audit_token.val[2];

	return bank_task;
};

// unlike XNU, the context always exists: it is created with the task and only destroyed with it
static bank_task_t get_bank_task_context(task_t task) {
	assert(task->bank_context != BANK_TASK_NULL);
	return task->bank_context;
};

void bank_task_initialize(task_t task) {
	task->bank_context = bank_task_alloc_init(task);
	if (task->bank_context == BANK_TASK_NULL) {
		panic("Failed to allocate a bank task");
	}
};

void dtape_bank_task_set_unique_pid(task_t task, uint64_t unique_pid) {
	get_bank_task_context(task)->bt_unique_pid = unique_pid;
};

void bank_task_destroy(task_t task) {
	bank_task_t bank_task = task->bank_context;
	task->bank_context = BANK_TASK_NULL;
	bank_task_dealloc(bank_task, 1);
};

// returns an account holding a made reference for the voucher system
static bank_account_t bank_account_alloc_init(bank_task_t bank_holder, bank_task_t bank_merchant,
	bank_task_t bank_secureoriginator, bank_task_t bank_proximateprocess, uint32_t persona_id)
{
	bank_account_t bank_account;

	lck_mtx_lock(&bank_lock);
	queue_iterate(&bank_holder->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay) {
		if (bank_account->ba_merchant != bank_merchant ||
		    bank_account->ba_secureoriginator != bank_secureoriginator ||
		    bank_account->ba_proximateprocess != bank_proximateprocess ||
		    bank_account->ba_so_persona_id != persona_id) {
			continue;
		}

		bank_account->ba_made++;
		lck_mtx_unlock(&bank_lock);
		return bank_account;
	}

	bank_account = malloc(sizeof(*bank_account));
	if (bank_account == BANK_ACCOUNT_NULL) {
		lck_mtx_unlock(&bank_lock);
		return BANK_ACCOUNT_NULL;
	}

	memset(bank_account, 0, sizeof(*bank_account));
	bank_account->ba_type = BANK_ACCOUNT;
	bank_account->ba_refs = 1; // the voucher system's reference
	bank_account->ba_made = 1;
	bank_account->ba_bill = LEDGER_NULL;
	bank_account->ba_holder = bank_holder;
	bank_account->ba_merchant = bank_merchant;
	bank_account->ba_secureoriginator = bank_secureoriginator;
	bank_account->ba_proximateprocess = bank_proximateprocess;
	bank_account->ba_so_persona_id = persona_id;
	queue_enter(&bank_holder->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay);
	lck_mtx_unlock(&bank_lock);

	bank_task_reference(bank_holder);
	bank_task_reference(bank_merchant);
	bank_task_reference(bank_secureoriginator);
	bank_task_reference(bank_proximateprocess);

	return bank_account;
};

static kern_return_t bank_account_dealloc_with_sync(bank_account_t bank_account, mach_voucher_attr_value_reference_t sync) {
	bank_task_t bank_holder = bank_account->ba_holder;

	lck_mtx_lock(&bank_lock);
	if (bank_account->ba_made != sync) {
		lck_mtx_unlock(&bank_lock);
		return KERN_FAILURE;
	}

	bank_account->ba_made -= sync;
	if (bank_account_release_num(bank_account, 1) > 1) {
		panic("Releasing a non zero ref bank account %p\n", bank_account);
	}
	queue_remove(&bank_holder->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay);
	lck_mtx_unlock(&bank_lock);

	bank_task_dealloc(bank_holder, 1);
	bank_task_dealloc(bank_account->ba_merchant, 1);
	bank_task_dealloc(bank_account->ba_secureoriginator, 1);
	bank_task_dealloc(bank_account->ba_proximateprocess, 1);
	free(bank_account);
	return KERN_SUCCESS;
};

// hands `bank_task` itself to the voucher system
static mach_voucher_attr_value_handle_t bank_task_made_handle(bank_task_t bank_task) {
	lck_mtx_lock(&bank_lock);
	bank_task->bt_made++;
	if (bank_task->bt_voucher_ref == 0) {
		// the voucher system holds a single reference while it has made references
		bank_task_reference(bank_task);
		bank_task->bt_voucher_ref = 1;
	}
	lck_mtx_unlock(&bank_lock);
	return BANK_ELEMENT_TO_HANDLE(bank_task);
};

// the element a value stands for in the current task; NULL for the default value
static bank_element_t bank_element_for_handle(mach_voucher_attr_value_handle_t handle) {
	bank_element_t bank_element = HANDLE_TO_BANK_ELEMENT(handle);
	if (bank_element == BANK_DEFAULT_TASK_VALUE) {
		bank_element = CAST_TO_BANK_ELEMENT(get_bank_task_context(current_task()));
	}
	if (bank_element != BANK_DEFAULT_VALUE && bank_element->be_type != BANK_TASK && bank_element->be_type != BANK_ACCOUNT) {
		panic("Bogus bank type: %d\n", bank_element->be_type);
	}
	return bank_element;
};

/*
 * BANK resource manager routines
 */

static kern_return_t bank_release_value(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_t value, mach_voucher_attr_value_reference_t sync)
{
	bank_element_t bank_element = HANDLE_TO_BANK_ELEMENT(value);

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	// the voucher system never releases the default values, which persist
	if (bank_element == BANK_DEFAULT_VALUE || bank_element == BANK_DEFAULT_TASK_VALUE) {
		return KERN_SUCCESS;
	}

	if (bank_element->be_type == BANK_TASK) {
		bank_task_t bank_task = CAST_TO_BANK_TASK(bank_element);

		lck_mtx_lock(&bank_lock);
		if (bank_task->bt_made != sync) {
			lck_mtx_unlock(&bank_lock);
			return KERN_FAILURE;
		}
		bank_task->bt_made -= sync;
		assert(bank_task->bt_voucher_ref == 1);
		bank_task->bt_voucher_ref = 0;
		lck_mtx_unlock(&bank_lock);

		bank_task_dealloc(bank_task, 1);
		return KERN_SUCCESS;
	}

	return bank_account_dealloc_with_sync(CAST_TO_BANK_ACCOUNT(bank_element), sync);
};

static kern_return_t bank_get_value(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_recipe_command_t command, mach_voucher_attr_value_handle_array_t prev_values,
	mach_msg_type_number_t prev_value_count, mach_voucher_attr_content_t recipe,
	mach_voucher_attr_content_size_t recipe_size, mach_voucher_attr_value_handle_t* out_value,
	mach_voucher_attr_value_flags_t* out_flags, ipc_voucher_t* out_value_voucher)
{
	bank_task_t bank_holder;
	bank_task_t bank_merchant;
	bank_task_t bank_secureoriginator;
	bank_task_t bank_proximateprocess;
	bank_account_t bank_account;
	uint32_t persona_id;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	// never an out voucher
	*out_value_voucher = IPC_VOUCHER_NULL;
	*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_NONE;

	switch (command) {
	case MACH_VOUCHER_ATTR_BANK_CREATE:
		// stands for the current task until MACH_VOUCHER_ATTR_SEND_PREPROCESS replaces it with the actual bank task
		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_TASK_VALUE);
		*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_PERSIST;
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA:
		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_VALUE);
		for (mach_msg_type_number_t i = 0; i < prev_value_count; i++) {
			bank_element_t bank_element = HANDLE_TO_BANK_ELEMENT(prev_values[i]);
			if (bank_element == BANK_DEFAULT_VALUE || bank_element == BANK_DEFAULT_TASK_VALUE) {
				continue;
			}
			// no task carries ENTITLEMENT_PERSONA_MODIFY: there are no personas to switch to
			return KERN_NO_ACCESS;
		}
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_AUTO_REDEEM:
		// accounts for the current task (the merchant) working on the voucher's behalf
		for (mach_msg_type_number_t i = 0; i < prev_value_count; i++) {
			bank_element_t bank_element = HANDLE_TO_BANK_ELEMENT(prev_values[i]);

			// the default task value never arrives over IPC
			if (bank_element == BANK_DEFAULT_VALUE || bank_element == BANK_DEFAULT_TASK_VALUE) {
				continue;
			}

			if (bank_element->be_type == BANK_TASK) {
				bank_holder = CAST_TO_BANK_TASK(bank_element);
				bank_secureoriginator = bank_holder;
				bank_proximateprocess = bank_holder;
				persona_id = bank_holder->bt_persona_id;
			} else {
				bank_account_t old_bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
				bank_holder = old_bank_account->ba_holder;
				bank_secureoriginator = old_bank_account->ba_secureoriginator;
				bank_proximateprocess = old_bank_account->ba_proximateprocess;
				persona_id = old_bank_account->ba_so_persona_id;
			}

			bank_merchant = get_bank_task_context(current_task());

			// redeeming for the task itself gives the default task value
			if (bank_holder == bank_merchant &&
			    bank_holder == bank_secureoriginator &&
			    bank_holder == bank_proximateprocess &&
			    persona_id == bank_holder->bt_persona_id) {
				*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_TASK_VALUE);
				*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_PERSIST;
				return KERN_SUCCESS;
			}

			bank_account = bank_account_alloc_init(bank_holder, bank_merchant, bank_secureoriginator,
				bank_proximateprocess, persona_id);
			if (bank_account == BANK_ACCOUNT_NULL) {
				return KERN_RESOURCE_SHORTAGE;
			}

			*out_value = BANK_ELEMENT_TO_HANDLE(bank_account);
			return KERN_SUCCESS;
		}

		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_VALUE);
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_SEND_PREPROCESS:
		// the current task is sending the voucher: it becomes the proximate process
		for (mach_msg_type_number_t i = 0; i < prev_value_count; i++) {
			bank_element_t bank_element = bank_element_for_handle(prev_values[i]);
			if (bank_element == BANK_DEFAULT_VALUE) {
				continue;
			}

			if (bank_element->be_type == BANK_TASK) {
				bank_holder = CAST_TO_BANK_TASK(bank_element);
				bank_secureoriginator = bank_holder;
				persona_id = bank_holder->bt_persona_id;
			} else {
				bank_account_t old_bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
				bank_holder = old_bank_account->ba_holder;
				bank_secureoriginator = old_bank_account->ba_secureoriginator;
				persona_id = old_bank_account->ba_so_persona_id;
			}

			bank_merchant = get_bank_task_context(current_task());

			if (!bank_merchant->bt_hasentitlement) {
				bank_secureoriginator = bank_merchant;
				persona_id = bank_merchant->bt_persona_id;
			}

			bank_proximateprocess = bank_merchant;

			// pre-processing for the task itself gives its bank task
			if (bank_holder == bank_merchant &&
			    bank_holder == bank_secureoriginator &&
			    bank_holder == bank_proximateprocess &&
			    persona_id == bank_holder->bt_persona_id) {
				*out_value = bank_task_made_handle(bank_holder);
				return KERN_SUCCESS;
			}

			bank_account = bank_account_alloc_init(bank_holder, bank_merchant, bank_secureoriginator,
				bank_proximateprocess, persona_id);
			if (bank_account == BANK_ACCOUNT_NULL) {
				return KERN_RESOURCE_SHORTAGE;
			}

			*out_value = BANK_ELEMENT_TO_HANDLE(bank_account);
			return KERN_SUCCESS;
		}

		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_VALUE);
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_REDEEM:
		// expects a value that was auto-redeemed for the current task
		for (mach_msg_type_number_t i = 0; i < prev_value_count; i++) {
			bank_element_t bank_element = HANDLE_TO_BANK_ELEMENT(prev_values[i]);
			bank_task_t bank_task = get_bank_task_context(current_task());

			if (bank_element == BANK_DEFAULT_VALUE) {
				continue;
			}

			if (bank_element == BANK_DEFAULT_TASK_VALUE ||
			    (bank_element->be_type == BANK_TASK && CAST_TO_BANK_TASK(bank_element) == bank_task)) {
				*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_TASK_VALUE);
				*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_PERSIST;
				return KERN_SUCCESS;
			}

			// lets userspace check whether the current task can adopt the voucher
			if (bank_element->be_type == BANK_TASK) {
				return KERN_INVALID_CAPABILITY;
			}

			bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
			if (bank_account->ba_merchant != bank_task) {
				return KERN_INVALID_CAPABILITY;
			}

			lck_mtx_lock(&bank_lock);
			bank_account->ba_made++;
			lck_mtx_unlock(&bank_lock);

			*out_value = BANK_ELEMENT_TO_HANDLE(bank_account);
			return KERN_SUCCESS;
		}

		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_VALUE);
		return KERN_SUCCESS;

	default:
		return KERN_INVALID_ARGUMENT;
	}
};

static kern_return_t bank_extract_content(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_array_t values, mach_msg_type_number_t value_count,
	mach_voucher_attr_recipe_command_t* out_command, mach_voucher_attr_content_t out_recipe,
	mach_voucher_attr_content_size_t* in_out_recipe_size)
{
	char buf[MACH_VOUCHER_BANK_CONTENT_SIZE];

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	for (mach_msg_type_number_t i = 0; i < value_count && *in_out_recipe_size > 0; i++) {
		bank_element_t bank_element = bank_element_for_handle(values[i]);
		if (bank_element == BANK_DEFAULT_VALUE) {
			continue;
		}

		if (MACH_VOUCHER_BANK_CONTENT_SIZE > *in_out_recipe_size) {
			*in_out_recipe_size = 0;
			return KERN_NO_SPACE;
		}

		if (bank_element->be_type == BANK_TASK) {
			snprintf(buf, MACH_VOUCHER_BANK_CONTENT_SIZE, " Bank Context for a pid %d\n", CAST_TO_BANK_TASK(bank_element)->bt_pid);
		} else {
			bank_account_t bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
			snprintf(buf, MACH_VOUCHER_BANK_CONTENT_SIZE,
				" Bank Account linking holder pid %d with merchant pid %d, originator PID/persona: %d, %u and proximate PID/persona: %d, %u\n",
				bank_account->ba_holder->bt_pid,
				bank_account->ba_merchant->bt_pid,
				bank_account->ba_secureoriginator->bt_pid,
				bank_account->ba_so_persona_id,
				bank_account->ba_proximateprocess->bt_pid,
				bank_account->ba_proximateprocess->bt_persona_id);
		}

		memcpy(&out_recipe[0], buf, strlen(buf) + 1);
		*out_command = MACH_VOUCHER_ATTR_BANK_NULL;
		*in_out_recipe_size = (mach_voucher_attr_content_size_t)strlen(buf) + 1;
		return KERN_SUCCESS;
	}

	return KERN_SUCCESS;
};

static kern_return_t bank_command(ipc_voucher_attr_manager_t manager, mach_voucher_attr_key_t key,
	mach_voucher_attr_value_handle_array_t values, mach_msg_type_number_t value_count,
	mach_voucher_attr_command_t command, mach_voucher_attr_content_t in_content,
	mach_voucher_attr_content_size_t in_content_size, mach_voucher_attr_content_t out_content,
	mach_voucher_attr_content_size_t* out_content_size)
{
	size_t needed;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	switch (command) {
	case BANK_ORIGINATOR_PID:
		needed = sizeof(int32_t);
		break;
	case BANK_PERSONA_TOKEN:
		needed = sizeof(struct persona_token);
		break;
	case BANK_PERSONA_ID:
		needed = sizeof(uint32_t);
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	if (needed > *out_content_size) {
		*out_content_size = 0;
		return KERN_NO_SPACE;
	}

	for (mach_msg_type_number_t i = 0; i < value_count; i++) {
		bank_element_t bank_element = bank_element_for_handle(values[i]);
		bank_task_t bank_task = CAST_TO_BANK_TASK(bank_element);
		bank_account_t bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
		bool is_task;

		if (bank_element == BANK_DEFAULT_VALUE) {
			continue;
		}

		is_task = bank_element->be_type == BANK_TASK;

		switch (command) {
		case BANK_ORIGINATOR_PID: {
			int32_t pid = is_task ? bank_task->bt_pid : bank_account->ba_holder->bt_pid;
			memcpy(out_content, &pid, sizeof(pid));
		} break;

		case BANK_PERSONA_TOKEN: {
			// only an account has an originator and a proximate process
			if (is_task) {
				*out_content_size = 0;
				return KERN_INVALID_OBJECT;
			}
			struct persona_token* token = (struct persona_token*)(void*)out_content;
			memcpy(&token->originator, &bank_account->ba_secureoriginator->bt_proc_persona, sizeof(struct proc_persona_info));
			memcpy(&token->proximate, &bank_account->ba_proximateprocess->bt_proc_persona, sizeof(struct proc_persona_info));
		} break;

		case BANK_PERSONA_ID: {
			uint32_t persona_id = is_task ? bank_task->bt_persona_id : bank_account->ba_so_persona_id;
			memcpy(out_content, &persona_id, sizeof(persona_id));
		} break;
		}

		*out_content_size = (mach_voucher_attr_content_size_t)needed;
		return KERN_SUCCESS;
	}

	// no value
	*out_content_size = 0;
	return KERN_INVALID_VALUE;
};

static void bank_release(ipc_voucher_attr_manager_t manager) {
	assert(manager == &bank_manager);
};

/*
 * Used by the IPC code
 */

kern_return_t bank_get_bank_ledger_thread_group_and_persona(ipc_voucher_t voucher, ledger_t* bankledger,
	struct thread_group** banktg, uint32_t* persona_id)
{
	if (persona_id != NULL) {
		mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
		mach_voucher_attr_value_handle_array_size_t val_count = MACH_VOUCHER_ATTR_VALUE_MAX_NESTED;
		bank_element_t bank_element = BANK_ELEMENT_NULL;

		if (mach_voucher_attr_control_get_values(bank_voucher_attr_control, voucher, vals, &val_count) == KERN_SUCCESS && val_count > 0) {
			bank_element = bank_element_for_handle(vals[0]);
		}

		if (bank_element != BANK_ELEMENT_NULL && bank_element->be_type == BANK_ACCOUNT) {
			*persona_id = CAST_TO_BANK_ACCOUNT(bank_element)->ba_so_persona_id;
		} else {
			*persona_id = get_bank_task_context(current_task())->bt_persona_id;
		}
	}

	// no ledgers or thread groups
	if (bankledger != NULL) {
		*bankledger = LEDGER_NULL;
	}
	if (banktg != NULL) {
		*banktg = NULL;
	}

	return KERN_SUCCESS;
};
