# frozen_string_literal: true

require 'spec_helper'

class PreloadedResourceProject < ActiveRecord::Base
  self.table_name = 'preloaded_resource_projects'
  has_many :preloaded_resource_tasks, class_name: 'PreloadedResourceTask',
                                      foreign_key: :preloaded_resource_project_id,
                                      inverse_of: :preloaded_resource_project
end

class PreloadedResourceTeam < ActiveRecord::Base
  self.table_name = 'preloaded_resource_teams'
  has_many :preloaded_resource_tasks, class_name: 'PreloadedResourceTask',
                                      foreign_key: :preloaded_resource_team_id,
                                      inverse_of: :preloaded_resource_team
end

class PreloadedResourceTask < ActiveRecord::Base
  self.table_name = 'preloaded_resource_tasks'
  belongs_to :preloaded_resource_project, class_name: 'PreloadedResourceProject',
                                          foreign_key: :preloaded_resource_project_id, optional: true
  belongs_to :preloaded_resource_team, class_name: 'PreloadedResourceTeam',
                                       foreign_key: :preloaded_resource_team_id, optional: true
end

class PreloadedResourceAbility
  include CanCan::Ability

  def initialize(user_id)
    can :read, PreloadedResourceTask, owner_id: user_id
    can :read, PreloadedResourceProject
    can :read, PreloadedResourceTeam
  end
end

# A controller shaped like the backend one: a shared before action preloads the record or the relation
# before CanCanCan runs, and the nested route names the parent through +:through+.
class PreloadedResourceTasksController
  include ActiveSupport::Callbacks
  include CanCan::ControllerAdditions

  define_callbacks :action

  class << self
    def before_action(*args, &block)
      set_callback(:action, :before, *args, &block)
    end
  end

  attr_accessor :params

  before_action :preload_resources
  load_and_authorize_resource :preloaded_resource_task,
                              through: %i[preloaded_resource_project preloaded_resource_team],
                              class: 'PreloadedResourceTask'

  def show
    @handled = @preloaded_resource_task
  end

  def index
    @handled = @preloaded_resource_tasks
  end

  def process(action)
    @handled = nil
    run_callbacks(:action) { public_send(action) }
    @handled
  end

  def current_ability
    @current_ability ||= PreloadedResourceAbility.new(params[:user_id])
  end

  def current_user
    params[:user_id]
  end

  private

  def preload_resources
    if params[:preloaded_resource_project_id]
      @preloaded_resource_project = PreloadedResourceProject.find(params[:preloaded_resource_project_id])
    end
    if params[:preloaded_resource_team_id]
      @preloaded_resource_team = PreloadedResourceTeam.find(params[:preloaded_resource_team_id])
    end
    @preloaded_resource_task = PreloadedResourceTask.find(params[:id]) if params[:id]
    @preloaded_resource_tasks = PreloadedResourceTask.where(id: params[:ids]) if params[:ids]
  end
end

# The same early preload without a nested route: the record is reused as before.
class PreloadedResourcePlainTasksController
  include ActiveSupport::Callbacks
  include CanCan::ControllerAdditions

  define_callbacks :action

  class << self
    def before_action(*args, &block)
      set_callback(:action, :before, *args, &block)
    end
  end

  attr_accessor :params

  before_action :preload_resources
  load_and_authorize_resource :preloaded_resource_task, class: 'PreloadedResourceTask'

  def show
    @handled = @preloaded_resource_task
  end

  def process(action)
    @handled = nil
    run_callbacks(:action) { public_send(action) }
    @handled
  end

  def current_ability
    @current_ability ||= PreloadedResourceAbility.new(params[:user_id])
  end

  def current_user
    params[:user_id]
  end

  private

  def preload_resources
    @preloaded_resource_task = PreloadedResourceTask.find(params[:id]) if params[:id]
  end
end

RSpec.describe 'preloaded resources and nested routes' do
  before :each do
    connect_db
    ActiveRecord::Migration.verbose = false

    ActiveRecord::Schema.define do
      create_table(:preloaded_resource_projects) { |t| t.string :name }
      create_table(:preloaded_resource_teams) { |t| t.string :name }
      create_table(:preloaded_resource_tasks) do |t|
        t.string :name
        t.integer :preloaded_resource_project_id
        t.integer :preloaded_resource_team_id
        t.integer :owner_id
      end
    end
    PreloadedResourceProject.reset_column_information
    PreloadedResourceTeam.reset_column_information
    PreloadedResourceTask.reset_column_information

    @project_a = PreloadedResourceProject.create!(name: 'project a')
    @project_b = PreloadedResourceProject.create!(name: 'project b')
    @team = PreloadedResourceTeam.create!(name: 'team')

    @task_a = PreloadedResourceTask.create!(name: 'a', preloaded_resource_project: @project_a, owner_id: 7)
    @task_b = PreloadedResourceTask.create!(name: 'b', preloaded_resource_project: @project_b, owner_id: 7)
    @task_other_owner = PreloadedResourceTask.create!(name: 'c', preloaded_resource_project: @project_a,
                                                      owner_id: 8)
    @task_team = PreloadedResourceTask.create!(name: 'team task', preloaded_resource_team: @team, owner_id: 7)
  end

  def routed_params(action, extra = {})
    { controller: 'preloaded_resource_tasks', action: action.to_s, user_id: 7 }.merge(extra)
  end

  def nested_controller(action, extra = {})
    controller = PreloadedResourceTasksController.new
    controller.params = routed_params(action, extra)
    controller
  end

  def handled_collection(action, extra = {})
    nested_controller(action, extra).process(action).to_a
  end

  def capture_sql
    queries = []
    subscription = ActiveSupport::Notifications.subscribe('sql.active_record') do |*args|
      payload = args.last
      queries << payload[:sql] unless %w[SCHEMA].include?(payload[:name])
    end
    result = yield
    [result, queries]
  ensure
    ActiveSupport::Notifications.unsubscribe(subscription)
  end

  describe 'a member action' do
    it 'reuses a preloaded record of the routed parent without looking it up again' do
      found = nil
      expect(PreloadedResourceTask).to receive(:find).once.and_wrap_original do |original, *args|
        found = original.call(*args)
      end

      controller = nested_controller(:show, id: @task_a.id, preloaded_resource_project_id: @project_a.id)
      handled, queries = capture_sql { controller.process(:show) }

      expect(handled).to equal(found)
      expect(handled.id).to eq(@task_a.id)
      expect(queries).to include(a_string_matching(/preloaded_resource_project_id/))
    end

    it 'accepts a record of the parent selected by the polymorphic route' do
      controller = nested_controller(:show, id: @task_team.id, preloaded_resource_team_id: @team.id)

      expect(controller.process(:show)).to eq(@task_team)
    end

    it 'rejects a preloaded record when the polymorphic route selects the other parent' do
      controller = nested_controller(:show, id: @task_a.id, preloaded_resource_team_id: @team.id)

      expect { controller.process(:show) }.to raise_error(CanCan::AccessDenied) do |error|
        expect(error.subject).to eq(PreloadedResourceTask)
      end
      expect(controller.instance_variable_get(:@handled)).to be_nil
    end

    it 'rejects a preloaded record of another parent before the action handles it' do
      controller = nested_controller(:show, id: @task_b.id, preloaded_resource_project_id: @project_a.id)

      expect { controller.process(:show) }.to raise_error(CanCan::AccessDenied) do |error|
        expect(error.action).to eq(:show)
        expect(error.subject).to eq(PreloadedResourceTask)
      end
      expect(controller.instance_variable_get(:@handled)).to be_nil
    end

    it 'rejects a preloaded record when the routed parent is missing' do
      controller = nested_controller(:show, id: @task_a.id)

      expect { controller.process(:show) }.to raise_error(CanCan::AccessDenied) do |error|
        expect(error.subject).to eq(PreloadedResourceTask)
      end
      expect(controller.instance_variable_get(:@handled)).to be_nil
    end

    it 'rejects a record of the routed parent that the operator cannot access' do
      controller = nested_controller(:show, id: @task_other_owner.id, preloaded_resource_project_id: @project_a.id)

      expect { controller.process(:show) }.to raise_error(CanCan::AccessDenied) do |error|
        expect(error.subject).to eq(@task_other_owner)
      end
      expect(controller.instance_variable_get(:@handled)).to be_nil
    end
  end

  describe 'a collection action' do
    it 'narrows a preloaded relation to the routed parent and the operator' do
      controller = nested_controller(:index, ids: [@task_a.id, @task_b.id, @task_other_owner.id],
                                             preloaded_resource_project_id: @project_a.id)

      handled, queries = capture_sql do
        controller.process(:index)
        controller.instance_variable_get(:@handled).to_a
      end
      handled = controller.instance_variable_get(:@handled)

      expect(handled.map(&:id)).to contain_exactly(@task_a.id)
      expect(handled.to_sql).to include('preloaded_resource_project_id')
      expect(handled.to_sql).to include('owner_id')
      expect(queries).to include(a_string_matching(/preloaded_resource_project_id/))
      expect(queries).to include(a_string_matching(/owner_id/))
    end

    it 'gives a different range of the same preloaded relation for another routed parent' do
      from_project_a = handled_collection(:index, ids: [@task_a.id, @task_b.id],
                                                  preloaded_resource_project_id: @project_a.id)
      from_project_b = handled_collection(:index, ids: [@task_a.id, @task_b.id],
                                                  preloaded_resource_project_id: @project_b.id)

      expect(from_project_a.map(&:id)).to contain_exactly(@task_a.id)
      expect(from_project_b.map(&:id)).to contain_exactly(@task_b.id)
    end

    it 'applies the operator conditions on top of the parent range' do
      handled = handled_collection(:index, ids: [@task_a.id, @task_other_owner.id], user_id: 8,
                                             preloaded_resource_project_id: @project_a.id)

      expect(handled.map(&:id)).to contain_exactly(@task_other_owner.id)
    end

    it 'rejects a preloaded relation when the routed parent is missing' do
      controller = nested_controller(:index, ids: [@task_a.id, @task_b.id])

      expect { controller.process(:index) }.to raise_error(CanCan::AccessDenied) do |error|
        expect(error.subject).to eq(PreloadedResourceTask)
      end
      expect(controller.instance_variable_get(:@handled)).to be_nil
    end
  end

  it 'keeps reusing an earlier query when the controller is not nested' do
    found = nil
    expect(PreloadedResourceTask).to receive(:find).once.and_wrap_original do |original, *args|
      found = original.call(*args)
    end

    controller = PreloadedResourcePlainTasksController.new
    controller.params = routed_params(:show, id: @task_b.id)

    expect(controller.process(:show)).to equal(found)
  end
end
