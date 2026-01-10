declare module 'worker-loader!*' {
  const WorkerConstructor: new () => Worker;
  export default WorkerConstructor;
}

declare module 'worker-loader!./crypto.worker.ts' {
  const WorkerConstructor: new () => Worker;
  export default WorkerConstructor;
}
