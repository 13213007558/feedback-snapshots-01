Add a layered application data store that serves a pre-filled shared cache read-only while generating the
seed images it is missing inside a project-owned private staging folder. The shared tree is never written to
or locked, every new image and lock lands in the private folder, and failed image builds reclaim their staging
directory.
