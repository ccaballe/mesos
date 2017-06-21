// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "authorizer/local/authorizerNetworks.hpp"

#include <string>
#include <vector>

#include <mesos/mesos.hpp>

#include <mesos/authorizer/acls.hpp>

#include <process/dispatch.hpp>
#include <process/future.hpp>
#include <process/id.hpp>
#include <process/process.hpp>
#include <process/protobuf.hpp>

#include <stout/foreach.hpp>
#include <stout/none.hpp>
#include <stout/option.hpp>
#include <stout/path.hpp>
#include <stout/protobuf.hpp>
#include <stout/try.hpp>

#include "common/parse.hpp"
#include "common/http.hpp"

//#include <stout/flags/parse.hpp>


using process::dispatch;
using process::Failure;
using process::Future;
using process::Owned;

using std::string;
using std::vector;

namespace mesos {
namespace internal {

struct GenericACL
{
	ACL::Entity subjects;
	ACL::Entity objects;
};



// TODO(mpark): This class exists to optionally carry `ACL::SetQuota` and
// `ACL::RemoveQuota` ACLs. This is a hack to support the deprecation cycle for
// `ACL::SetQuota` and `ACL::RemoveQuota`. This can be removed / replaced with
// `vector<GenericACL>` at the end of deprecation cycle which started with 1.0.
struct GenericACLs
{
	GenericACLs(const vector<GenericACL>& acls_) : acls(acls_) {}

	GenericACLs(
			const vector<GenericACL>& acls_,
			const vector<GenericACL>& set_quotas_,
			const vector<GenericACL>& remove_quotas_)
	: acls(acls_), set_quotas(set_quotas_), remove_quotas(remove_quotas_) {}

	vector<GenericACL> acls;

	// These ACLs are set iff the authorization action is `UPDATE_QUOTA`.
	Option<vector<GenericACL>> set_quotas;
	Option<vector<GenericACL>> remove_quotas;
};


// Match matrix:
//
//                  -----------ACL----------
//
//                    SOME    NONE    ANY
//          -------|-------|-------|-------
//  |        SOME  | Yes/No|  Yes  |   Yes
//  |       -------|-------|-------|-------
// Request   NONE  |  No   |  Yes  |   No
//  |       -------|-------|-------|-------
//  |        ANY   |  No   |  Yes  |   Yes
//          -------|-------|-------|-------
static bool matches(const ACL::Entity& request, const ACL::Entity& acl)
{
	// NONE only matches with NONE.
	if (request.type() == ACL::Entity::NONE) {
		return acl.type() == ACL::Entity::NONE;
	}

	// ANY matches with ANY or NONE.
	if (request.type() == ACL::Entity::ANY) {
		return acl.type() == ACL::Entity::ANY || acl.type() == ACL::Entity::NONE;
	}

	if (request.type() == ACL::Entity::SOME) {
		// SOME matches with ANY or NONE.
		if (acl.type() == ACL::Entity::ANY || acl.type() == ACL::Entity::NONE) {
			return true;
		}

		// SOME is allowed if the request values are a subset of ACL
		// values.
		foreach (const string& value, request.values()) {
			bool found = false;
			foreach (const string& value_, acl.values()) {
				if (value == value_) {
					found = true;
					break;
				}
			}

			if (!found) {
				return false;
			}
		}
		return true;
	}

	return false;
}

// Allow matrix:
//
//                 -----------ACL----------
//
//                    SOME    NONE    ANY
//          -------|-------|-------|-------
//  |        SOME  | Yes/No|  No   |   Yes
//  |       -------|-------|-------|-------
// Request   NONE  |  No   |  Yes  |   No
//  |       -------|-------|-------|-------
//  |        ANY   |  No   |  No   |   Yes
//          -------|-------|-------|-------
static bool allows(const ACL::Entity& request, const ACL::Entity& acl)
{
	// NONE is only allowed by NONE.
	if (request.type() == ACL::Entity::NONE) {
		return acl.type() == ACL::Entity::NONE;
	}

	// ANY is only allowed by ANY.
	if (request.type() == ACL::Entity::ANY) {
		return acl.type() == ACL::Entity::ANY;
	}

	if (request.type() == ACL::Entity::SOME) {
		// SOME is allowed by ANY.
		if (acl.type() == ACL::Entity::ANY) {
			return true;
		}

		// SOME is not allowed by NONE.
		if (acl.type() == ACL::Entity::NONE) {
			return false;
		}

		// SOME is allowed if the request values are a subset of ACL
		// values.
		foreach (const string& value, request.values()) {
			bool found = false;
			foreach (const string& value_, acl.values()) {
				if (value == value_) {
					found = true;
					break;
				}
			}

			if (!found) {
				return false;
			}
		}
		return true;
	}

	return false;
}


class LocalAuthorizerNetworkObjectApprover : public ObjectApprover
{
public:
	LocalAuthorizerNetworkObjectApprover(
			const GenericACLs& acls,
			const Option<authorization::Subject>& subject,
			const authorization::Action& action,
			const bool permissive,
			const std::vector<AclRunTask> networkAcls
			)
	: acls_(acls),
	  subject_(subject),
	  action_(action),
	  permissive_(permissive),
	  networkAcls_(networkAcls)
	{}

	virtual Try<bool> approved(
			const Option<ObjectApprover::Object>& object) const noexcept override
			{


		// Construct subject.
		ACL::Entity aclSubject;
		if (subject_.isSome()) {
			aclSubject.add_values(subject_->value());
			aclSubject.set_type(mesos::ACL::Entity::SOME);


		} else {
			aclSubject.set_type(mesos::ACL::Entity::ANY);
		}

		// Construct object.
		ACL::Entity aclObject;

		if (object.isNone()) {

			aclObject.set_type(mesos::ACL::Entity::ANY);
		} else {
			switch (action_) {
			// All actions using `object.value` for authorization.
			case authorization::REGISTER_FRAMEWORK_WITH_ROLE:
			case authorization::TEARDOWN_FRAMEWORK_WITH_PRINCIPAL:
			case authorization::RESERVE_RESOURCES_WITH_ROLE:
			case authorization::UNRESERVE_RESOURCES_WITH_PRINCIPAL:
			case authorization::CREATE_VOLUME_WITH_ROLE:
			case authorization::DESTROY_VOLUME_WITH_PRINCIPAL:
			case authorization::GET_QUOTA_WITH_ROLE:
			case authorization::VIEW_ROLE:
			case authorization::UPDATE_WEIGHT_WITH_ROLE:
			case authorization::GET_ENDPOINT_WITH_PATH: {
				// Check object has the required types set.
				CHECK_NOTNULL(object->value);

				aclObject.add_values(*(object->value));
				aclObject.set_type(mesos::ACL::Entity::SOME);

				break;
			}
			case authorization::RUN_TASK: {
				aclObject.set_type(mesos::ACL::Entity::SOME);

				int nNetworks = object->task_info->container().network_infos().size();
				if (nNetworks > 1){
					LOG(ERROR) << "ERROR Only one net has supported" ;
					return false;
				}
				// TODO default behaviour is value of permissive in json. Must be global to all aclRunTask
				bool netMatch = networkAcls_[0].permissive;
				string networkTaskInfo = "";
				if (nNetworks ==  1)
					networkTaskInfo =  object->task_info->container().network_infos().Get(0).name();
				// TODO check object->task_info->command().user() vs object->framework_info->user()
				string userTaskInfo = object->framework_info->user();

				string principalTaskInfo = subject_->value();

				for (AclRunTask aclRunTask: networkAcls_){
					std::vector<string> users = aclRunTask.users.values;
					std::vector<string> principals = aclRunTask.principals.values;
					std::vector<string> networks = aclRunTask.networks.values;

					if ( networkMatch(networks, networkTaskInfo, aclRunTask.networks.type)
							&& userMatch(users, userTaskInfo, aclRunTask.users.type)
							&& principalMatch(principals, principalTaskInfo, aclRunTask.principals.type)
							){
						netMatch = true;
					}
				}

				if (!netMatch) {
					LOG(ERROR) << "Network authorization deny";
					return false;
				}

				if (object->task_info && object->task_info->has_command() &&
						object->task_info->command().has_user()) {
					aclObject.add_values(object->task_info->command().user());
				} else if (object->task_info && object->task_info->has_executor() &&
						object->task_info->executor().command().has_user()) {
					aclObject.add_values(
							object->task_info->executor().command().user());
				} else if (object->framework_info) {
					aclObject.add_values(object->framework_info->user());
				} else {
					aclObject.set_type(mesos::ACL::Entity::ANY);
				}
				break;
			}
			case authorization::ACCESS_MESOS_LOG: {
				aclObject.set_type(mesos::ACL::Entity::ANY);

				break;
			}
			case authorization::VIEW_FLAGS: {
				aclObject.set_type(mesos::ACL::Entity::ANY);

				break;
			}
			case authorization::ACCESS_SANDBOX: {
				aclObject.set_type(mesos::ACL::Entity::ANY);

				if (object->executor_info != nullptr &&
						object->executor_info->command().has_user()) {
					aclObject.add_values(object->executor_info->command().user());
					aclObject.set_type(mesos::ACL::Entity::SOME);
				} else if (object->framework_info != nullptr) {
					aclObject.add_values(object->framework_info->user());
					aclObject.set_type(mesos::ACL::Entity::SOME);
				}

				break;
			}
			case authorization::UPDATE_QUOTA: {
				// Check object has the required types set.
				CHECK_NOTNULL(object->quota_info);

				// TODO(mpark): This is a hack to support the deprecation cycle for
				// `ACL::SetQuota` and `ACL::RemoveQuota`. This block of code can be
				// removed at the end of deprecation cycle which started with 1.0.
				if (acls_.set_quotas->size() > 0 || acls_.remove_quotas->size() > 0) {
					CHECK_NOTNULL(object->value);
					if (*object->value == "SetQuota") {
						aclObject.add_values(object->quota_info->role());
						aclObject.set_type(mesos::ACL::Entity::SOME);

						CHECK_SOME(acls_.set_quotas);
						return approved(acls_.set_quotas.get(), aclSubject, aclObject);
					} else if (*object->value == "RemoveQuota") {
						if (object->quota_info->has_principal()) {
							aclObject.add_values(object->quota_info->principal());
							aclObject.set_type(mesos::ACL::Entity::SOME);
						} else {
							aclObject.set_type(mesos::ACL::Entity::ANY);
						}

						CHECK_SOME(acls_.remove_quotas);
						return approved(acls_.remove_quotas.get(), aclSubject, aclObject);
					}
				}

				aclObject.add_values(object->quota_info->role());
				aclObject.set_type(mesos::ACL::Entity::SOME);

				break;
			}
			case authorization::VIEW_FRAMEWORK: {
				// Check object has the required types set.
				CHECK_NOTNULL(object->framework_info);

				aclObject.add_values(object->framework_info->user());
				aclObject.set_type(mesos::ACL::Entity::SOME);

				break;
			}
			case authorization::VIEW_TASK: {
				CHECK(object->task != nullptr || object->task_info != nullptr);
				CHECK_NOTNULL(object->framework_info);

				// First we consider either whether `Task` or `TaskInfo`
				// have `user` set. As fallback we use `FrameworkInfo.user`.
				Option<string> taskUser = None();
				if (object->task != nullptr && object->task->has_user()) {
					taskUser = object->task->user();
				} else if (object->task_info != nullptr) {
					// Within TaskInfo the user can be either set in `command`
					// or `executor.command`.
					if (object->task_info->has_command() &&
							object->task_info->command().has_user()) {
						taskUser = object->task_info->command().user();
					} else if (object->task_info->has_executor() &&
							object->task_info->executor().command().has_user()) {
						taskUser = object->task_info->executor().command().user();
					}
				}

				// In case there is no `user` set on task level we fallback
				// to the `FrameworkInfo.user`.
				if (taskUser.isNone()) {
					taskUser = object->framework_info->user();
				}
				aclObject.add_values(taskUser.get());
				aclObject.set_type(mesos::ACL::Entity::SOME);

				break;
			}
			case authorization::VIEW_EXECUTOR: {
				CHECK_NOTNULL(object->executor_info);
				CHECK_NOTNULL(object->framework_info);

				if (object->executor_info->command().has_user()) {
					aclObject.add_values(object->executor_info->command().user());
					aclObject.set_type(mesos::ACL::Entity::SOME);
				} else {
					aclObject.add_values(object->framework_info->user());
					aclObject.set_type(mesos::ACL::Entity::SOME);
				}

				break;
			}
			case authorization::UNKNOWN:
				LOG(WARNING) << "Authorization for action '" << action_
				<< "' is not defined and therefore not authorized";
				return false;
				break;
			}
		}

		return approved(acls_.acls, aclSubject, aclObject);
			}

private:
	bool approved(
			const vector<GenericACL>& acls,
			const ACL::Entity& subject,
			const ACL::Entity& object) const
	{
		// Authorize subject/object.
		foreach (const GenericACL& acl, acls) {

			if (matches(subject, acl.subjects) && matches(object, acl.objects)) {

				acl.objects.PrintDebugString();
				return allows(subject, acl.subjects) && allows(object, acl.objects);
			}
		}

		return permissive_; // None of the ACLs match.
	}

	bool principalMatch(const std::vector<string> principals, const string principalsTaskInfo, const string type) const {
		if (type.compare("ANY") == 0)
			return true;
		if (type.compare("NONE") == 0)
			return false;
		return std::find(principals.begin(), principals.end(), principalsTaskInfo) != principals.end();
	}

	bool userMatch(const std::vector<string> users, const string usersTaskInfo, const string type) const {
		if (type.compare("ANY") == 0)
			return true;
		if (type.compare("NONE") == 0)
			return false;
		return std::find(users.begin(), users.end(), usersTaskInfo) != users.end();
	}

	bool networkMatch(const std::vector<std::string> networks, const string networkTaskInfo, const string type) const {
		if (type.compare("ANY") == 0)
			return true;
		if (type.compare("NONE") == 0)
			return false;
		return std::find(networks.begin(), networks.end(), networkTaskInfo) != networks.end();
	}


	const GenericACLs acls_;
	const Option<authorization::Subject> subject_;
	const authorization::Action action_;
	const bool permissive_;
	const std::vector<AclRunTask> networkAcls_;
};



class LocalAuthorizerNetworkProcess : public ProtobufProcess<LocalAuthorizerNetworkProcess>
{
public:
	LocalAuthorizerNetworkProcess(const ACLs& _acls, const std::vector<AclRunTask> _networkAcls)
	: ProcessBase(process::ID::generate("authorizer")), acls(_acls), networkAcls(_networkAcls) {


	}

	virtual void initialize()
	{
		// TODO(zhitao): Remove the following log warning at the end of the
		// deprecation cycle which started with 1.0.
		if (acls.set_quotas_size() > 0 ||
				acls.remove_quotas_size() > 0) {
			LOG(WARNING) << "SetQuota and RemoveQuota ACLs are deprecated; "
					<< "please use UpdateQuota";
		}

		// TODO(arojas): Remove the following two if blocks once
		// ShutdownFramework reaches the end of deprecation cycle
		// which started with 0.27.0.
		if (acls.shutdown_frameworks_size() > 0 &&
				acls.teardown_frameworks_size() > 0) {
			LOG(WARNING) << "ACLs defined for both ShutdownFramework and "
					<< "TeardownFramework; only the latter will be used";
			return;
		}

		// Move contents of `acls.shutdown_frameworks` to
		// `acls.teardown_frameworks`
		if (acls.shutdown_frameworks_size() > 0) {
			LOG(WARNING) << "ShutdownFramework ACL is deprecated; please use "
					<< "TeardownFramework";
			foreach (const ACL::ShutdownFramework& acl, acls.shutdown_frameworks()) {
				ACL::TeardownFramework* teardown = acls.add_teardown_frameworks();
				teardown->mutable_principals()->CopyFrom(acl.principals());
				teardown->mutable_framework_principals()->CopyFrom(
						acl.framework_principals());
			}
		}
		acls.clear_shutdown_frameworks();
	}

	Future<bool> authorized(const authorization::Request& request)
								  {
		return getObjectApprover(request.subject(), request.action())
				.then([=](const Owned<ObjectApprover>& objectApprover) -> Future<bool> {
			Option<ObjectApprover::Object> object = None();
			if (request.has_object()) {
				object = ObjectApprover::Object(request.object());
			}

			Try<bool> result = objectApprover->approved(object);
			if (result.isError()) {
				return Failure(result.error());
			}
			return result.get();
		});
								  }

	Future<Owned<ObjectApprover>> getObjectApprover(
			const Option<authorization::Subject>& subject,
			const authorization::Action& action)
			{

		// Implementation of the ObjectApprover interface denying all objects.
		class RejectingObjectApprover : public ObjectApprover
		{
		public:
			virtual Try<bool> approved(
					const Option<ObjectApprover::Object>& object) const noexcept override
					{
				return false;
					}
		};

		// Generate GenericACLs.
		Result<GenericACLs> genericACLs = createGenericACLs(action, acls);

		if (genericACLs.isError()) {
			return Failure(genericACLs.error());
		}

		if (genericACLs.isNone()) {
			// If we could not create acls, we deny all objects.
			return Owned<ObjectApprover>(new RejectingObjectApprover());
		}




		return Owned<ObjectApprover>(
				new LocalAuthorizerNetworkObjectApprover(
						genericACLs.get(), subject, action, acls.permissive(), networkAcls));
			}

private:
	static Result<GenericACLs> createGenericACLs(
			const authorization::Action& action,
			const ACLs& acls)
			{
		vector<GenericACL> acls_;


		switch (action) {
		case authorization::REGISTER_FRAMEWORK_WITH_ROLE:

			foreach (
					const ACL::RegisterFramework& acl, acls.register_frameworks()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();
				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::TEARDOWN_FRAMEWORK_WITH_PRINCIPAL:
			foreach (
					const ACL::TeardownFramework& acl, acls.teardown_frameworks()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.framework_principals();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::RUN_TASK:
			foreach (const ACL::RunTask& acl, acls.run_tasks()) {

				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.users();

				// TODO meter en acl_.objects el net ademas del user

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::RESERVE_RESOURCES_WITH_ROLE:
			foreach (const ACL::ReserveResources& acl, acls.reserve_resources()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::UNRESERVE_RESOURCES_WITH_PRINCIPAL:
			foreach (
					const ACL::UnreserveResources& acl, acls.unreserve_resources()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.reserver_principals();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::CREATE_VOLUME_WITH_ROLE:
			foreach (const ACL::CreateVolume& acl, acls.create_volumes()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::DESTROY_VOLUME_WITH_PRINCIPAL:
			foreach (const ACL::DestroyVolume& acl, acls.destroy_volumes()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.creator_principals();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::GET_QUOTA_WITH_ROLE:
			foreach (const ACL::GetQuota& acl, acls.get_quotas()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::UPDATE_QUOTA: {
			foreach (const ACL::UpdateQuota& acl, acls.update_quotas()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			vector<GenericACL> set_quotas;
			foreach (const ACL::SetQuota& acl, acls.set_quotas()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				set_quotas.push_back(acl_);
			}

			vector<GenericACL> remove_quotas;
			foreach (const ACL::RemoveQuota& acl, acls.remove_quotas()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.quota_principals();

				remove_quotas.push_back(acl_);
			}

			return GenericACLs(acls_, set_quotas, remove_quotas);
			break;
		}
		case authorization::VIEW_ROLE:
			foreach (const ACL::ViewRole& acl, acls.view_roles()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::UPDATE_WEIGHT_WITH_ROLE:
			foreach (const ACL::UpdateWeight& acl, acls.update_weights()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.roles();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::GET_ENDPOINT_WITH_PATH:
			foreach (const ACL::GetEndpoint& acl, acls.get_endpoints()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.paths();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::ACCESS_MESOS_LOG:
			foreach (const ACL::AccessMesosLog& acl, acls.access_mesos_logs()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.logs();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::VIEW_FLAGS:
			foreach (const ACL::ViewFlags& acl, acls.view_flags()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.flags();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::ACCESS_SANDBOX: {
			foreach (const ACL::AccessSandbox& acl, acls.access_sandboxes()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.users();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		}
		case authorization::VIEW_FRAMEWORK:
			foreach (const ACL::ViewFramework& acl, acls.view_frameworks()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.users();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::VIEW_TASK:
			foreach (const ACL::ViewTask& acl, acls.view_tasks()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.users();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::VIEW_EXECUTOR:
			foreach (const ACL::ViewExecutor& acl, acls.view_executors()) {
				GenericACL acl_;
				acl_.subjects = acl.principals();
				acl_.objects = acl.users();

				acls_.push_back(acl_);
			}

			return acls_;
			break;
		case authorization::UNKNOWN:
			// Cannot generate acls for an unknown action.
			return None();
			break;
		}
		UNREACHABLE();
			}

	ACLs acls;
	const std::vector<AclRunTask> networkAcls;

};


Try<Authorizer*> LocalAuthorizerNetworks::create(const ACLs& acls, const std::vector<AclRunTask> networkAcls)
{
	Option<Error> validationError = validate(acls);
	if (validationError.isSome()) {
		return validationError.get();
	}

	Authorizer* local = new LocalAuthorizerNetworks(acls, networkAcls);

	return local;
}


Try<Authorizer*> LocalAuthorizerNetworks::create(const Parameters& parameters)
{
	Option<string> acls;

	std::vector<AclRunTask> networkAcls;

	foreach (const Parameter& parameter, parameters.parameter()) {
		if (parameter.key() == "acls") {
			bool permissive;
			acls = parameter.value();

			Try<JSON::Object> json = flags::parse<JSON::Object>(parameter.value());

			Result<JSON::Boolean> permissiveResult = json.get().find<JSON::Boolean>("permissive");

			if(permissiveResult.isNone())
				permissive = true;
			else
				permissive = permissiveResult.get().value;

			Result<JSON::Array> a = json.get().find<JSON::Array>("run_tasks");
			std::vector<JSON::Value> vector = a.get().values;

			for (std::vector<int>::size_type i = 0; i != vector.size(); i++){
				AclRunTask aclRunTask;
				// TODO permissive is duplicated in every acl run task
				aclRunTask.permissive = permissive;
				JSON::Value element = vector[i];
				JSON::Object oneObject = element.as<JSON::Object>();

				Result<JSON::Array> principals = oneObject.find<JSON::Array>("principals.values");
				// if no values, get type parameter
				if(principals.isSome()){
					std::vector<JSON::Value> principalsStr = principals.get().values;

					for (std::vector<int>::size_type j = 0; j != principalsStr.size(); j++){
						string princ = stringify(principalsStr[j]);
						princ.erase(remove(princ.begin(), princ.end(), '\"'), princ.end());
						aclRunTask.principals.values.push_back(princ);
					}
				}
				else {
					Result<JSON::String> principalsType = oneObject.find<JSON::String>("principals.type");
					if(principalsType.isNone() || principalsType.isError()){
						LOG(ERROR) << "Error parsing principals. Check that you have configured some values or type" ;
						return Error("Error parsing principals. Check that you have configured some values or type");
					}
					else if((principalsType.get().value.compare("ANY") == 0) || (principalsType.get().value.compare("NONE") == 0)){
						aclRunTask.principals.type = principalsType.get().value;
					}
					else {
						LOG(ERROR) << "Error parsing principals. Type values allowed are ANY or NONE" ;
						return Error("Error parsing principals. Type values allowed are ANY or NONE");
					}
				}

				Result<JSON::Array> users = oneObject.find<JSON::Array>("users.values");
				if(users.isSome()){

					std::vector<JSON::Value> usersStr = users.get().values;

					for (std::vector<int>::size_type j = 0; j != usersStr.size(); j++){
						string user = stringify(usersStr[j]);
						user.erase(remove(user.begin(), user.end(), '\"'), user.end());

						aclRunTask.users.values.push_back(user);
					}
				}
				else {
					Result<JSON::String> usersType = oneObject.find<JSON::String>("users.type");
					if(usersType.isNone() || usersType.isError()){
						LOG(ERROR) << "Error parsing users. Check that you have configured some values or type" ;
						return Error("Error parsing users. Check that you have configured some values or type");
					}
					else if((usersType.get().value.compare("ANY") == 0) || (usersType.get().value.compare("NONE") == 0)){
						aclRunTask.users.type = usersType.get().value;
					}
					else {
						LOG(ERROR) << "Error parsing users. Type values allowed are ANY or NONE" ;
						return Error("Error parsing users. Type values allowed are ANY or NONE");
					}
				}

				Result<JSON::Array> networks = oneObject.find<JSON::Array>("networks.values");
				if(networks.isSome()){
					std::vector<JSON::Value> networksStr = networks.get().values;
					for (std::vector<int>::size_type j = 0; j != networksStr.size(); j++){
						string network = stringify(networksStr[j]);
						network.erase(remove(network.begin(), network.end(), '\"'), network.end());

						aclRunTask.networks.values.push_back(network);
					}
				}
				else {
					Result<JSON::String> networksType = oneObject.find<JSON::String>("networks.type");
					if(networksType.isNone() || networksType.isError()){
						LOG(ERROR) << "Error parsing networks. Check that you have configured some values or type" ;
						return Error("Error parsing networks. Check that you have configured some values or type");
					}
					else if((networksType.get().value.compare("ANY") == 0) || (networksType.get().value.compare("NONE") == 0)){
						aclRunTask.networks.type = networksType.get().value;
					}
					else {
						LOG(ERROR) << "Error parsing networks. Type values allowed are ANY or NONE" ;
						return Error("Error parsing networks. Type values allowed are ANY or NONE");
					}
				}

				networkAcls.push_back(aclRunTask);
			}

		}
	}

	if (acls.isNone()) {
		return Error("No ACLs for default authorizer provided");
	}
	Try<ACLs> acls_ = flags::parse<ACLs>(acls.get());
	if (acls_.isError()) {
		return Error("Contents of 'acls' parameter could not be parsed into a "
				"valid ACLs object");
	}


	return LocalAuthorizerNetworks::create(acls_.get(), networkAcls);
}


Option<Error> LocalAuthorizerNetworks::validate(const ACLs& acls)
{
	if (acls.update_quotas_size() > 0 &&
			(acls.set_quotas_size() > 0 || acls.remove_quotas_size() > 0)) {
		return Error("acls.update_quotas cannot be used "
				"together with deprecated set_quotas/remove_quotas!");
	}


	foreach (const ACL::AccessMesosLog& acl, acls.access_mesos_logs()) {
		if (acl.logs().type() == ACL::Entity::SOME) {

			return Error("acls.access_mesos_logs type must be either NONE or ANY");
		}
	}

	foreach (const ACL::ViewFlags& acl, acls.view_flags()) {
		if (acl.flags().type() == ACL::Entity::SOME) {

			return Error("acls.view_flags type must be either NONE or ANY");
		}
	}

	foreach (const ACL::GetEndpoint& acl, acls.get_endpoints()) {
		if (acl.paths().type() == ACL::Entity::SOME) {
			foreach (const string& path, acl.paths().values()) {
				if (!AUTHORIZABLE_ENDPOINTS.contains(path)) {

					return Error("Path: '" + path + "' is not an authorizable path");
				}
			}
		}
	}


	// TODO(alexr): Consider validating not only protobuf, but also the original
	// JSON in order to spot misspelled names. A misspelled action may affect
	// authorization result and hence lead to a security issue (e.g. when there
	// are entries with same action but different subjects or objects).

	return None();
}


LocalAuthorizerNetworks::LocalAuthorizerNetworks(const ACLs& acls, std::vector<AclRunTask> networkAcls)
: process(new LocalAuthorizerNetworkProcess(acls, networkAcls))
{


	spawn(process);
}


LocalAuthorizerNetworks::~LocalAuthorizerNetworks()
{
	if (process != nullptr) {
		terminate(process);
		wait(process);
		delete process;
	}
}


process::Future<bool> LocalAuthorizerNetworks::authorized(
		const authorization::Request& request)
{


	// Request sanity checks.
	// A set `subject` should always come with a set `value`.
	CHECK(
			!request.has_subject() ||
			(request.has_subject() && request.subject().has_value()));

	// A set `action` is mandatory.
	CHECK(request.has_action());

	// A set `object` should always come with at least one set union
	// style value.
	CHECK(
			!request.has_object() ||
			(request.has_object() &&
					(request.object().has_value() ||
							request.object().has_framework_info() ||
							request.object().has_task() ||
							request.object().has_task_info() ||
							request.object().has_executor_info() ||
							request.object().has_quota_info())));

	typedef Future<bool> (LocalAuthorizerNetworkProcess::*F)(
			const authorization::Request&);

	return dispatch(
			process,
			static_cast<F>(&LocalAuthorizerNetworkProcess::authorized),
			request);
}


Future<Owned<ObjectApprover>> LocalAuthorizerNetworks::getObjectApprover(
		const Option<authorization::Subject>& subject,
		const authorization::Action& action)
{

	return dispatch(
			process,
			&LocalAuthorizerNetworkProcess::getObjectApprover,
			subject,
			action);
}

} // namespace internal {
} // namespace mesos {
