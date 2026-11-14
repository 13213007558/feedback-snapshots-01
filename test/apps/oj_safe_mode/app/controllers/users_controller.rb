class UsersController < ApplicationController
  def some_api
    Oj.load(params[:json])                       # line 3: global default is provably safe
    Oj.load(params[:json], mode: :strict)        # line 4: explicit safe mode (must never warn)
    Oj.load(params[:json], mode: :object)        # line 5: call-level object mode overrides safe default
    Oj.load(params[:json], mode: ENV["OJ_MODE"]) # line 6: call-level mode is not a resolvable constant
    Oj.object_load(params[:json])                # line 7: object_load is always unsafe
  end
end
