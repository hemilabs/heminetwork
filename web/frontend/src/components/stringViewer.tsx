const CopyIcon = () => (
  <svg fill="none" height={16} width={16} xmlns="http://www.w3.org/2000/svg">
    <path
      d="M10 6V2.333A.333.333 0 0 0 9.667 2H2.333A.333.333 0 0 0 2 2.333v7.334c0 .184.15.333.333.333H6m.333-4h7.334c.184 0 .333.15.333.333v7.334c0 .184-.15.333-.333.333H6.333A.333.333 0 0 1 6 13.667V6.333C6 6.15 6.15 6 6.333 6Z"
      stroke="#737373"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={1.333}
    />
  </svg>
)

const ViewTextIcon = () => (
  <svg fill="none" height={16} width={16} xmlns="http://www.w3.org/2000/svg">
    <path
      d="m1.334 8-.592-.306L.583 8l.159.306L1.334 8Zm13.333 0 .592.306.159-.306-.159-.306-.592.306Zm-12.74.306C3.444 5.37 5.768 4 8 4c2.231 0 4.556 1.37 6.074 4.306l1.184-.612c-1.7-3.287-4.432-5.027-7.258-5.027-2.826 0-5.56 1.74-7.26 5.027l1.185.612Zm-1.185 0c1.7 3.287 4.433 5.027 7.259 5.027 2.826 0 5.559-1.74 7.258-5.027l-1.184-.612C12.557 10.63 10.232 12 8.001 12c-2.232 0-4.556-1.37-6.075-4.306l-1.184.612ZM9.334 8c0 .736-.597 1.333-1.333 1.333v1.334A2.667 2.667 0 0 0 10.667 8H9.334ZM8.001 9.333A1.333 1.333 0 0 1 6.667 8H5.334a2.667 2.667 0 0 0 2.667 2.667V9.333ZM6.667 8c0-.736.597-1.333 1.334-1.333V5.333A2.667 2.667 0 0 0 5.334 8h1.333Zm1.334-1.333c.736 0 1.333.597 1.333 1.333h1.333a2.667 2.667 0 0 0-2.666-2.667v1.334Z"
      fill="#737373"
    />
  </svg>
)

type Props = {
  text: string
  title: string
}

export const StringViewer = function ({ text, title }: Props) {
  return (
    <div className="flex w-full flex-col gap-y-1 rounded-lg bg-neutral-100 p-2">
      <span>{title}</span>
      <div className="flex w-full flex-shrink items-center gap-x-3 bg-white p-2 text-sm font-medium leading-normal">
        <span className="overflow-x-hidden text-ellipsis whitespace-nowrap">
          {text}
        </span>
        <ViewTextIcon />
        <CopyIcon />
      </div>
    </div>
  )
}
