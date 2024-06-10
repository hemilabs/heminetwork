import { StringViewer } from 'components/stringViewer'
import { ReactNode, useState } from 'react'

type SourceOfPrivateKey = 'generate' | 'import'

const GeneratePkIcon = () => (
  <svg fill="none" height={16} width={16} xmlns="http://www.w3.org/2000/svg">
    <path
      d="m3.394 13.188.272-.535-.272.535Zm-.583-.583.535-.272-.535.272Zm10.376 0-.534-.272.534.272Zm-.582.583-.273-.535.273.535Zm.582-9.793-.534.272.534-.272Zm-.582-.583-.273.535.273-.535Zm-9.794.583-.534-.273.534.273Zm.583-.583-.272-.535.272.535ZM11.266 6a.6.6 0 1 0-1.2 0h1.2Zm-1.2 4a.6.6 0 1 0 1.2 0h-1.2Zm2.667-5.2v6.4h1.2V4.8h-1.2Zm-1.534 7.933H4.8v1.2h6.4v-1.2ZM3.266 11.2V4.8h-1.2v6.4h1.2Zm1.533-7.933h6.4v-1.2H4.8v1.2Zm0 9.466c-.383 0-.634 0-.827-.016-.185-.015-.262-.041-.306-.064l-.544 1.07c.24.123.493.169.753.19.252.02.56.02.924.02v-1.2ZM2.066 11.2c0 .364 0 .672.02.925.021.259.068.511.19.753l1.07-.545c-.022-.044-.049-.12-.064-.306a11.38 11.38 0 0 1-.016-.827h-1.2Zm1.6 1.453a.733.733 0 0 1-.32-.32l-1.07.545c.186.364.482.66.846.845l.544-1.07Zm9.067-1.453c0 .383 0 .635-.017.827-.015.185-.04.262-.063.306l1.069.545c.123-.242.17-.494.19-.753.021-.253.02-.562.02-.925h-1.2Zm-1.534 2.733c.364 0 .672 0 .925-.02a1.97 1.97 0 0 0 .753-.19l-.545-1.07c-.044.023-.12.049-.306.064-.192.016-.443.016-.827.016v1.2Zm1.454-1.6a.734.734 0 0 1-.32.32l.544 1.07c.364-.186.66-.482.845-.845l-1.07-.545Zm1.28-7.533c0-.363 0-.672-.02-.925a1.971 1.971 0 0 0-.191-.753l-1.07.545c.023.044.05.12.065.306.015.192.016.444.016.827h1.2Zm-2.734-1.533c.384 0 .635 0 .827.016.185.015.262.041.306.064l.545-1.07a1.97 1.97 0 0 0-.753-.19c-.253-.02-.561-.02-.925-.02v1.2Zm2.523-.145a1.934 1.934 0 0 0-.845-.845l-.545 1.07c.138.07.25.182.32.32l1.07-.545ZM3.266 4.8c0-.383 0-.635.016-.827.015-.185.042-.262.064-.306l-1.07-.545a1.97 1.97 0 0 0-.19.753c-.02.253-.02.562-.02.925h1.2Zm1.533-2.733c-.363 0-.672 0-.924.02a1.97 1.97 0 0 0-.753.19l.544 1.07c.044-.023.121-.049.306-.064.193-.016.444-.016.827-.016v-1.2Zm-1.453 1.6a.733.733 0 0 1 .32-.32l-.544-1.07c-.364.186-.66.482-.845.845l1.069.545ZM10.066 6v4h1.2V6h-1.2Z"
      fill="#0A0A0A"
    />
    <path
      d="M5.333 8.583a.583.583 0 1 0 0-1.166.583.583 0 0 0 0 1.166Zm2.667 0a.583.583 0 1 0 0-1.166.583.583 0 0 0 0 1.166Z"
      fill="#0A0A0A"
      stroke="#0A0A0A"
      strokeWidth={0.5}
    />
  </svg>
)

const ImportPkIcon = () => (
  <svg fill="none" height={16} width={16} xmlns="http://www.w3.org/2000/svg">
    <path
      d="m11.241 2.991 1.125-1.125a1.25 1.25 0 0 1 1.768 1.768l-7.08 7.08a2.998 2.998 0 0 1-1.264.753L4 12l.533-1.79a3 3 0 0 1 .754-1.265l5.954-5.954Zm0 0L13 4.75m-1 4.583V12.5a1.5 1.5 0 0 1-1.5 1.5h-7A1.5 1.5 0 0 1 2 12.5v-7A1.5 1.5 0 0 1 3.5 4h3.167"
      stroke="#0A0A0A"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
)

const PrivateKey = ({ source }: { source: SourceOfPrivateKey }) =>
  source === 'generate' ? (
    <StringViewer
      text="2b2cba0f8b22a1d98a10f14f8b95b5f99a7c81539b1d410ab469234f19ca4f9e"
      title="Private Key"
    />
  ) : (
    <input />
  )

type RadioBoxProps = {
  checked: boolean
  icon: ReactNode
  id: SourceOfPrivateKey
  label: string
  onChange: () => void
}
const RadioBox = ({ checked, icon, id, label, onChange }: RadioBoxProps) => (
  <div className="rounded-lg border border-solid border-zinc-300/55 p-3 ">
    {icon}
    <div className="mt-2 flex items-center gap-x-3">
      <label htmlFor={id}>{label}</label>
      <input
        checked={checked}
        id={id}
        name="source-private-key"
        type="radio"
        onChange={onChange}
      />
    </div>
  </div>
)

export const ManagePage = function () {
  const [sourceOfPrivateKey, setSourceOfPrivateKey] =
    useState<SourceOfPrivateKey>('generate')
  return (
    <div className="grid-cols-3-column-layout grid w-full">
      <div className="col-start-2 mx-auto max-w-lg">
        <div className="rounded-3xl border border-solid border-slate-100 bg-white p-6 md:p-9">
          <div className="flex w-full flex-col gap-y-4 bg-white">
            <h2 className="text-2xl font-medium leading-tight text-neutral-950">
              Input or generate your Private Key...
            </h2>
            <p className="text-base leading-normal text-neutral-500">
              Choose between generating a new Private Key or inputting an
              existing one.
            </p>
            <div className="flex items-center gap-x-5">
              <RadioBox
                checked={sourceOfPrivateKey === 'generate'}
                icon={<GeneratePkIcon />}
                id="generate"
                label="Generate a Private Key"
                onChange={() => setSourceOfPrivateKey('generate')}
              />
              <RadioBox
                checked={sourceOfPrivateKey === 'import'}
                icon={<ImportPkIcon />}
                id="import"
                label="Input your own Private Key"
                onChange={() => setSourceOfPrivateKey('import')}
              />
            </div>
            <div className="h-px w-full border border-solid border-zinc-300/55" />
            <PrivateKey source={sourceOfPrivateKey} />
            <div className="mt-5">
              <button className="h-14 w-full cursor-pointer rounded-xl bg-orange-950 text-base text-white hover:bg-opacity-80">
                Continue
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
